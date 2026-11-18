package management

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretboundary"
)

func TestAuthWritersRejectSecretHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.json")
	const original = `{"type":"fake","token":"fixture-real-token"}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	// The prefix is escaped to check decoded values as well as raw bytes.
	bad := []byte(`{"type":"fake","token":"\u0063px_h1_AAAAAAAAAAAAAAAAAAAAAAAAAA_0000"}`)
	h := &Handler{}
	for _, write := range []func() error{
		func() error { return h.writeAuthFileBytes(path, bad, nil) },
		func() error { return writeV8AuthFilePayload(path, bad) },
	} {
		if err := write(); !errors.Is(err, secretboundary.ErrHandleInStorage) {
			t.Fatal("auth writer accepted a handle")
		}
		saved, err := os.ReadFile(path)
		if err != nil || string(saved) != original {
			t.Fatal("rejected auth write modified the file")
		}
	}
}
