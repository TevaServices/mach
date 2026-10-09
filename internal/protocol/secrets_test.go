package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// The secrets frames' contract is mostly about what they must NOT carry: a
// value. These tests pin the wire shapes — the field names another
// implementation (the control plane's side of each frame) will encode against,
// and the absence of any value field on every frame that travels unsealed.
func TestSecretFrameShapes(t *testing.T) {
	t.Run("announce carries names only", func(t *testing.T) {
		raw := marshalEnvelope(t, "secrets_announce", SecretsAnnounce{Org: "bcross", Names: []string{"DB_PASSWORD", "API_KEY"}})
		var env map[string]any
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		if env["type"] != "secrets_announce" {
			t.Errorf("type = %v", env["type"])
		}
		p, ok := env["payload"].(map[string]any)
		if !ok {
			t.Fatalf("payload = %v", env["payload"])
		}
		if p["org"] != "bcross" {
			t.Errorf("org = %v", p["org"])
		}
		names, ok := p["names"].([]any)
		if !ok || len(names) != 2 {
			t.Fatalf("names = %v", p["names"])
		}
		if _, has := p["value"]; has {
			t.Error("secrets_announce carries a value field — it must not")
		}
	})

	t.Run("push result carries name and status only", func(t *testing.T) {
		raw, err := json.Marshal(SecretPushResult{Name: "DB_PASSWORD", OK: false, Error: "unknown secret name"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "value") {
			t.Errorf("secret_push_result carries a value field: %s", raw)
		}
		var back SecretPushResult
		if err := json.Unmarshal(raw, &back); err != nil || back.Name != "DB_PASSWORD" || back.OK {
			t.Errorf("round trip = %+v (%v)", back, err)
		}
	})

	t.Run("list result carries org and names", func(t *testing.T) {
		raw, err := json.Marshal(SecretListResult{Org: "bcross", Names: []string{"API_KEY"}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "value") {
			t.Errorf("secret_list_result carries a value field: %s", raw)
		}
	})

	t.Run("sealed push mirrors the sealed exec shape", func(t *testing.T) {
		raw, err := json.Marshal(SealedSecretPush{SealedB64: "AAA", ReplyPub: "bb"})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"sealed_b64":"AAA","reply_pub":"bb"}`
		if string(raw) != want {
			t.Errorf("SealedSecretPush = %s, want %s", raw, want)
		}
	})

	t.Run("ack is a count", func(t *testing.T) {
		raw, err := json.Marshal(SecretsAnnounceAck{Count: 3})
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != `{"count":3}` {
			t.Errorf("SecretsAnnounceAck = %s", raw)
		}
	})

	t.Run("payload round trip", func(t *testing.T) {
		raw, err := json.Marshal(SecretPayload{Name: "DB_PASSWORD", Org: "bcross", Value: "s3cr3tvalue", CreatedAt: "t"})
		if err != nil {
			t.Fatal(err)
		}
		var back SecretPayload
		if err := json.Unmarshal(raw, &back); err != nil || back.Value != "s3cr3tvalue" || back.Org != "bcross" {
			t.Errorf("round trip = %+v (%v)", back, err)
		}
	})
}

func marshalEnvelope(t *testing.T, typ string, payload any) []byte {
	t.Helper()
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Envelope{Type: typ, Payload: p})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
