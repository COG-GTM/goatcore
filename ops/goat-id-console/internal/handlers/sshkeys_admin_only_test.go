package handlers

// The SSH-key queue and its decisions are admin-only. Approval is the only
// control between a submitted public key and a host shell, so a
// sponsorship-authorized non-admin must be refused on the page and on every
// decision, and the row must stay untouched.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/usareur-af/goatcore/ops/goat-id-console/internal/onboardstore"
)

func newSSHKeySponsorServer(t *testing.T) *Server {
	t.Helper()
	s := newOnboardTestServer(t)
	s.Cfg.DevBypassAuth = false
	portalURL, _ := fakeSponsorPortal(t, nil, map[string]sponsorLookupResponse{
		"sponsor@example.org": {Org: "0ff404dd", SponsorAuthorized: true, SponsorMaxTier: "developer"},
	})
	s.Cfg.PortalInternalURL = portalURL
	s.Cfg.PortalLookupToken = "svc-token"
	return s
}

func sshKeyStatus(t *testing.T, s *Server, id string) string {
	t.Helper()
	k, err := s.Onboard.SSHKeyByID(context.Background(), id)
	if err != nil {
		t.Fatalf("read key %s: %v", id, err)
	}
	return k.Status
}

func TestSSHKeyQueue_adminOnly(t *testing.T) {
	s := newSSHKeySponsorServer(t)
	h := s.Routes()
	submitted := submitKey(t, s, "cand-submitted")
	approved := submitKey(t, s, "cand-approved")
	if err := s.Onboard.ApproveSSHKey(context.Background(), approved, "setup"); err != nil {
		t.Fatalf("seed approved key: %v", err)
	}

	get := func(email, groups string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/onboarding/ssh-keys?status=all", nil)
		r.Header.Set("X-Forwarded-Email", email)
		r.Header.Set("X-Forwarded-Groups", groups)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := get("sponsor@example.org", "DEVELOPER")
	if w.Code != http.StatusForbidden {
		t.Fatalf("sponsor queue GET = %d, want 403", w.Code)
	}
	for _, leak := range []string{"cand-submitted", "cand-approved", submitted, approved} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("sponsor queue GET leaked %q", leak)
		}
	}
	if w := get("admin@example.org", "ADMINS"); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "/ssh-keys/"+submitted+"/approve") {
		t.Fatalf("admin queue GET = %d, want 200 with the approve control; %.300s", w.Code, w.Body.String())
	}

	form := url.Values{"csrf": {s.csrfNonce}}
	for _, tc := range []struct{ id, action, want string }{
		{submitted, "approve", onboardstore.SSHKeySubmitted},
		{submitted, "reject", onboardstore.SSHKeySubmitted},
		{approved, "revoke", onboardstore.SSHKeyApproved},
	} {
		w := browserForm(t, h, "sponsor@example.org", "DEVELOPER", "/ssh-keys/"+tc.id+"/"+tc.action, form)
		if w.Code != http.StatusForbidden {
			t.Fatalf("sponsor %s = %d, want 403", tc.action, w.Code)
		}
		if got := sshKeyStatus(t, s, tc.id); got != tc.want {
			t.Fatalf("row after sponsor %s = %q, want untouched %q", tc.action, got, tc.want)
		}
	}

	if w := browserForm(t, h, "admin@example.org", "ADMINS", "/ssh-keys/"+submitted+"/approve", form); w.Code != http.StatusOK {
		t.Fatalf("admin approve = %d, want 200; %.300s", w.Code, w.Body.String())
	}
	if got := sshKeyStatus(t, s, submitted); got != onboardstore.SSHKeyApproved {
		t.Fatalf("row after admin approve = %q, want approved", got)
	}
}

// The handlers refuse a sponsor session themselves, so re-registering a route
// behind the sponsor-admitting gate cannot reopen the queue.
func TestSSHKeyHandlers_refuseSponsorSession(t *testing.T) {
	s := newSSHKeySponsorServer(t)
	id := submitKey(t, s, "cand-handler")

	r := httptest.NewRequestWithContext(context.Background(), "GET", "/onboarding/ssh-keys", nil)
	r.Header.Set("X-Forwarded-Email", "sponsor@example.org")
	r.Header.Set("X-Forwarded-Groups", "DEVELOPER")
	w := httptest.NewRecorder()
	s.onboardGate(s.handleSSHKeysQueue)(w, r)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "cand-handler") {
		t.Fatalf("sponsor queue handler = %d, want 403 with no rows", w.Code)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /ssh-keys/{id}/{action}", s.onboardGate(s.handleSSHKeyDecision))
	form := url.Values{"csrf": {s.csrfNonce}}
	if w := browserForm(t, mux, "sponsor@example.org", "DEVELOPER", "/ssh-keys/"+id+"/approve", form); w.Code != http.StatusForbidden {
		t.Fatalf("sponsor decision handler = %d, want 403", w.Code)
	}
	if got := sshKeyStatus(t, s, id); got != onboardstore.SSHKeySubmitted {
		t.Fatalf("row after sponsor decision = %q, want untouched submitted", got)
	}
}
