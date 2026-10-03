package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// ENTER proceeds; anything else aborts before a single enrollment prompt.
func TestConfirmTrustedOrigin(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"enter proceeds", "\n", ""},
		{"typed word refuses", "no\n", "aborted"},
		{"typed space refuses", " \n", "aborted"},
		{"eof refuses", "", "aborted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			bootStdin = bufio.NewReader(strings.NewReader(tc.input))
			defer func() { bootStdin = bufio.NewReader(strings.NewReader("")) }()
			err := confirmTrustedOrigin(&out)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("ENTER should proceed, got %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("input %q should abort, got %v", tc.input, err)
			}
			if !strings.Contains(out.String(), "personally know and trust") {
				t.Error("the warning text is missing its social-engineering sentence")
			}
		})
	}
}
