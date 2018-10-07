package dhparam

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func execGeneratorIntegration(t *testing.T, bitsize, generator int) {
	dh, err := Generate(bitsize, generator, nil)
	if err != nil {
		t.Fatalf("Unable to generate DH params: %s", err)
	}

	pem, err := dh.ToPEM()
	if err != nil {
		t.Fatalf("Unable to generate PEM encoded version: %s", err)
	}

	buf := new(bytes.Buffer)

	cmd := exec.Command("openssl", "dhparam", "-inform", "PEM", "-in", "-", "-check", "-noout", "-text")
	cmd.Stdin = bytes.NewReader(pem)
	cmd.Stdout = buf
	cmd.Stderr = buf

	if err := cmd.Run(); err != nil {
		t.Errorf("Validation command was not successful: %s", err)
	}

	result := buf.String()
	fullOutput := false

	for _, expect := range []string{
		fmt.Sprintf("DH Parameters: (%d bit)", bitsize),
		"DH parameters appear to be ok.",
		fmt.Sprintf("generator: %d (0x%x)", generator, generator),
	} {
		if !strings.Contains(result, expect) {
			t.Errorf("Did not find expected OpenSSL output: %q", expect)
			fullOutput = true
		}
	}

	if fullOutput {
		t.Logf("Received OpenSSL output:\n%s", result)
	}
}

func TestGenerator512bit(t *testing.T) {
	execGeneratorIntegration(t, 512, 2)
}

func TestGenerator1024bit(t *testing.T) {
	execGeneratorIntegration(t, 1024, 2)
}

func TestGenerator2048bit(t *testing.T) {
	execGeneratorIntegration(t, 2048, 2)
}

func TestGenerator5(t *testing.T) {
	execGeneratorIntegration(t, 512, 5)
}
