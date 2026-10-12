// sealsecret is test-support tooling for scripts/e2e.sh, not a shipped
// command: the web UI's push is browser-sealed, and the suite cannot drive a
// browser, so this helper produces the same artifact the browser's wasm
// produces — a sealed SecretPayload for one machine's E2E key. It is the
// internal/e2e seal, not a second implementation of it, so what the suite
// posts is byte-shape-identical to what a real operator's browser posts.
//
// Usage (value on stdin, like `mach secrets push --value-file -`):
//
//	go run ./scripts/sealsecret --key <pub-e2e-hex> --name NAME --org ORG < value
//
// It prints only the sealed blob on stdout; the value is never echoed.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/TevaServices/mach/internal/e2e"
	"github.com/TevaServices/mach/internal/protocol"
)

func main() {
	key := flag.String("key", "", "the target machine's public E2E key (hex)")
	name := flag.String("name", "", "secret name")
	org := flag.String("org", "", "org the machine belongs to")
	flag.Parse()
	if *key == "" || *name == "" || *org == "" {
		fmt.Fprintln(os.Stderr, "usage: sealsecret --key <pub-e2e-hex> --name NAME --org ORG  (value on stdin)")
		os.Exit(2)
	}
	pub, err := hex.DecodeString(*key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sealsecret: the public E2E key is not hex: "+err.Error())
		os.Exit(2)
	}
	value, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sealsecret: reading stdin: "+err.Error())
		os.Exit(2)
	}
	// One trailing newline is editor/pipe residue, exactly as the console's
	// own --value-file reader strips it.
	for len(value) > 0 && (value[len(value)-1] == '\n' || value[len(value)-1] == '\r') {
		value = value[:len(value)-1]
	}
	payload, err := json.Marshal(protocol.SecretPayload{
		Name:  *name,
		Org:   *org,
		Value: string(value),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sealsecret: "+err.Error())
		os.Exit(2)
	}
	sealed, err := e2e.Seal(pub, payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sealsecret: "+err.Error())
		os.Exit(2)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sealed))
}
