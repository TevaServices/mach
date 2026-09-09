package store

import "crypto/sha256"

func sha256sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hexEncode(h[:])
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return string(out)
}