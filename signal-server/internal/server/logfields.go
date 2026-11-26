package server

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	signalpb "github.com/usareur-af/goatcore/signal-server/gen/signalexchange"
)

// cidPrefixBytes bounds how much of the body correlationID hashes. Ordinary
// ICE offers (~260 B) fit whole, so their IDs are plain sha256(body)[:4].
// A Rosenpass offer is ~524 KB; hashing all of it cost ~2 ms of CPU per
// relay hop on a CPU without SHA extensions, the largest single cost on the
// Send path, to produce 4 bytes of log field.
const cidPrefixBytes = 4096

// correlationID derives a short, stable identifier for an EncryptedMessage
// that can be grepped across signal-server node logs. It's stable across
// federation hops because the encrypted body is bitwise identical on every
// node that sees this message: A's inbound Send, A's outbound Forward, B's
// Forward handler, and B's delivery to the target peer's stream.
//
// Format: 8 hex chars. A body of at most cidPrefixBytes gives
// sha256(body)[:4]; a longer body gives sha256(len(body) as 8-byte
// little-endian ‖ body[:cidPrefixBytes])[:4]. The body is NaCl-box
// ciphertext, so its first 4 KiB are as distinct as the whole of it.
// Collisions are possible but at our signaling write rate (single-digit
// transactions per minute) we'll never see one. If that changes, widen the
// slice.
func correlationID(msg *signalpb.EncryptedMessage) string {
	body := msg.GetBody()
	if len(body) == 0 {
		return "no-body"
	}
	if len(body) <= cidPrefixBytes {
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:4])
	}
	h := sha256.New()
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(body)))
	h.Write(n[:])
	h.Write(body[:cidPrefixBytes])
	return hex.EncodeToString(h.Sum(nil)[:4])
}
