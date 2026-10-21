//go:build unix

package captcha

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCapSecretFIFOIsRejectedWithoutWriter(t *testing.T) {
	if path := os.Getenv("CHEESEWAF_TEST_CAP_FIFO"); path != "" {
		var err error
		if os.Getenv("CHEESEWAF_TEST_CAP_SWAP") == "1" {
			before, statErr := statCapSecretFile(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = readCapSecretFile(path, before)
		} else {
			_, err = NewCapVerifierFromFile("https://cap.example.test/siteverify", path, time.Second)
		}
		if !errors.Is(err, errCapSecretFile) {
			t.Fatalf("FIFO returned %v, want secret-file rejection", err)
		}
		assertDoesNotLeakCredentials(t, err, path)
		return
	}
	for _, mode := range []string{"already-fifo", "swapped-after-stat"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret-fifo")
			if mode == "already-fifo" {
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			// Isolate a regression in a killable process: a blocking open must not
			// leave a goroutine behind or hold the application's activation mutex.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCapSecretFIFOIsRejectedWithoutWriter$", "-test.timeout=5s")
			cmd.Env = append(os.Environ(), "CHEESEWAF_TEST_CAP_FIFO="+path)
			if mode == "swapped-after-stat" {
				cmd.Env = append(cmd.Env, "CHEESEWAF_TEST_CAP_SWAP=1")
			}
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("secret-file activation blocked on a FIFO without a writer")
			}
			if err != nil {
				t.Fatalf("FIFO rejection failed: %v\n%s", err, output)
			}
		})
	}
}

func TestCapSecretSymlinkIsRejected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "secret")
	if err := os.WriteFile(path, []byte("private-cap-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "secret-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	_, err := NewCapVerifierFromFile("https://cap.example.test/siteverify", link, time.Second)
	if !errors.Is(err, errCapSecretFile) {
		t.Fatalf("symlink returned %v, want secret-file rejection", err)
	}
	assertDoesNotLeakCredentials(t, err, link, "private-cap-secret")
}
