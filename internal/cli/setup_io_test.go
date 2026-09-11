package cli

import (
	"strings"
	"testing"
)

func TestWizardReadLinePreservesIdentityWhitespace(t *testing.T) {
	w := newWizardIO(strings.NewReader(" admin \n"), &strings.Builder{})
	got, err := w.readLine()
	if err != nil {
		t.Fatal(err)
	}
	if got != " admin " {
		t.Fatalf("readLine() = %q, want original whitespace preserved", got)
	}
}

func TestWizardReadLinePreservesExtraCarriageReturn(t *testing.T) {
	w := newWizardIO(strings.NewReader("admin\r\r\n"), &strings.Builder{})
	got, err := w.readLine()
	if err != nil {
		t.Fatal(err)
	}
	if got != "admin\r" {
		t.Fatalf("readLine() = %q, want one transport CR removed and extra control byte preserved", got)
	}
}
