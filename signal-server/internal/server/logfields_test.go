package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	signalpb "github.com/usareur-af/goatcore/signal-server/gen/signalexchange"
)

func TestCorrelationIDSmallBodyIsSHA256Prefix(t *testing.T) {
	for _, n := range []int{1, 260, cidPrefixBytes} {
		body := bytes.Repeat([]byte{0xA5}, n)
		sum := sha256.Sum256(body)
		want := hex.EncodeToString(sum[:4])
		if got := correlationID(&signalpb.EncryptedMessage{Body: body}); got != want {
			t.Errorf("len %d: correlationID = %q, want sha256(body)[:4] = %q", n, got, want)
		}
	}
}

func TestCorrelationIDLargeBody(t *testing.T) {
	body := make([]byte, 524288)
	for i := range body {
		body[i] = byte(i * 7)
	}
	cid := correlationID(&signalpb.EncryptedMessage{Body: body})
	if len(cid) != 8 {
		t.Fatalf("cid %q: want 8 hex chars", cid)
	}
	if again := correlationID(&signalpb.EncryptedMessage{Body: append([]byte(nil), body...)}); again != cid {
		t.Errorf("same body gave %q then %q; must be stable across hops", cid, again)
	}
	if got := correlationID(&signalpb.EncryptedMessage{Body: body[:len(body)-1]}); got == cid {
		t.Errorf("bodies of different length share cid %q", cid)
	}
	changed := append([]byte(nil), body...)
	changed[0] ^= 0xFF
	if got := correlationID(&signalpb.EncryptedMessage{Body: changed}); got == cid {
		t.Errorf("bodies with different first byte share cid %q", cid)
	}
}

func TestCorrelationIDEmptyBody(t *testing.T) {
	if got := correlationID(&signalpb.EncryptedMessage{}); got != "no-body" {
		t.Errorf("correlationID(empty) = %q, want no-body", got)
	}
}
