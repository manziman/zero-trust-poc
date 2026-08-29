package keymaterial_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manziman/custody/internal/keymaterial"
)

func TestLoadOrCreatePersistsKeyAndPublishesPublicOnlyJWKS(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "issuer.key")
	first, err := keymaterial.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := keymaterial.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("issuer key changed across reload")
	}
	wire, err := keymaterial.JWKS(first.Public(), "txn-current")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(`"d"`)) {
		t.Fatal("JWKS exposed private key material")
	}
	keys, err := keymaterial.ParseEd25519JWKS(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys["txn-current"], first.Public().(ed25519.PublicKey)) {
		t.Fatal("parsed JWKS key differs from issuer public key")
	}
}

func TestPublishEd25519PublicKeyAtomicallyReplacesPublicMaterial(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nested", "db-current.pub")

	for range 2 {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := keymaterial.PublishEd25519PublicKey(path, publicKey); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(contents)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded, publicKey) {
			t.Fatal("published key differs from issuer public key")
		}
	}
}
