// Package keymaterial owns the minimal local-development key lifecycle. It
// persists private seeds in non-shared volumes and exposes only public JWKS.
package keymaterial

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func LoadOrCreate(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("key path is required")
	}
	contents, err := os.ReadFile(path)
	if err == nil {
		return decodeSeed(contents)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read issuer key: %w", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate issuer key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("read concurrently created issuer key: %w", readErr)
		}
		return decodeSeed(contents)
	}
	if err != nil {
		return nil, fmt.Errorf("create issuer key: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(seed) + "\n"
	if _, err := file.WriteString(encoded); err != nil {
		file.Close()
		return nil, fmt.Errorf("write issuer key: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, fmt.Errorf("sync issuer key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close issuer key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func decodeSeed(contents []byte) (ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(contents)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("issuer key file does not contain an Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublishEd25519PublicKey atomically publishes the raw, base64url-encoded
// public key consumed by the PostgreSQL OAuth validator. The private issuer key
// never leaves the token service's private key volume.
func PublishEd25519PublicKey(path string, key ed25519.PublicKey) error {
	if path == "" || len(key) != ed25519.PublicKeySize {
		return errors.New("public-key path and Ed25519 public key are required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create public-key directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".database-public-key-*")
	if err != nil {
		return fmt.Errorf("create temporary public-key file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return fmt.Errorf("set public-key permissions: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key) + "\n"
	if _, err := temporary.WriteString(encoded); err != nil {
		temporary.Close()
		return fmt.Errorf("write public key: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync public key: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close public key: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish public key: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open public-key directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync public-key directory: %w", err)
	}
	return nil
}

// JWKS renders one Ed25519 public key using the RFC 8037 OKP representation.
func JWKS(public crypto.PublicKey, keyID string) ([]byte, error) {
	key, ok := public.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize || keyID == "" {
		return nil, errors.New("Ed25519 public key and key ID are required")
	}
	document := struct {
		Keys []map[string]string `json:"keys"`
	}{Keys: []map[string]string{{
		"kty": "OKP",
		"crv": "Ed25519",
		"use": "sig",
		"alg": "EdDSA",
		"kid": keyID,
		"x":   base64.RawURLEncoding.EncodeToString(key),
	}}}
	return json.Marshal(document)
}

// ParseEd25519JWKS validates Custody's public-only issuer key-set profile.
func ParseEd25519JWKS(wire []byte) (map[string]ed25519.PublicKey, error) {
	var document struct {
		Keys []struct {
			KeyType   string `json:"kty"`
			Curve     string `json:"crv"`
			Use       string `json:"use"`
			Algorithm string `json:"alg"`
			KeyID     string `json:"kid"`
			X         string `json:"x"`
			Private   string `json:"d"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(wire, &document); err != nil {
		return nil, fmt.Errorf("decode Ed25519 JWKS: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, candidate := range document.Keys {
		if candidate.KeyType != "OKP" || candidate.Curve != "Ed25519" || candidate.Use != "sig" || candidate.Algorithm != "EdDSA" || candidate.KeyID == "" || candidate.Private != "" {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(candidate.X)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key %s", candidate.KeyID)
		}
		if _, exists := keys[candidate.KeyID]; exists {
			return nil, fmt.Errorf("duplicate JWKS key ID %s", candidate.KeyID)
		}
		keys[candidate.KeyID] = ed25519.PublicKey(decoded)
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable Ed25519 signing keys")
	}
	return keys, nil
}

// FetchEd25519JWKS downloads and validates a bounded public key set.
func FetchEd25519JWKS(ctx context.Context, client *http.Client, endpoint string) (map[string]ed25519.PublicKey, error) {
	if client == nil || endpoint == "" {
		return nil, errors.New("JWKS client and endpoint are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch Ed25519 JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch Ed25519 JWKS: status %s", response.Status)
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > 1024*1024 {
		return nil, errors.New("JWKS exceeds one MiB")
	}
	return ParseEd25519JWKS(wire)
}
