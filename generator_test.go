package dhparam

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func execGeneratorIntegration(t *testing.T, bitsize int, generator Generator) {
	dh, err := Generate(bitsize, generator, nil)
	if err != nil {
		t.Fatalf("Unable to generate DH params: %s", err)
	}

	pem, err := dh.ToPEM()
	if err != nil {
		t.Fatalf("Unable to generate PEM encoded version: %s", err)
	}

	buf := new(bytes.Buffer)

	f, err := ioutil.TempFile("", "dhparam.*")
	if err != nil {
		t.Fatalf("Unable to create tempfile: %s", err)
	}
	defer os.Remove(f.Name())

	if _, err = f.Write(pem); err != nil {
		t.Fatalf("Unable to write tempfile: %s", err)
	}

	f.Close()

	cmd := exec.Command("openssl", "dhparam", "-inform", "PEM", "-in", f.Name(), "-check", "-noout", "-text")
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
	execGeneratorIntegration(t, 512, GeneratorTwo)
}

func TestGenerator1024bit(t *testing.T) {
	execGeneratorIntegration(t, 1024, GeneratorTwo)
}

func TestGenerator2048bit(t *testing.T) {
	execGeneratorIntegration(t, 2048, GeneratorTwo)
}

func TestGenerator5(t *testing.T) {
	execGeneratorIntegration(t, 512, GeneratorFive)
}
