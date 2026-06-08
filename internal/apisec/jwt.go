package apisec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type parsedJWT struct {
	header       map[string]any
	claims       map[string]any
	alg          string
	kid          string
	signingInput []byte
	signature    []byte
}

type jwtVerifier struct {
	allowed map[string]struct{}
	keys    []jwtKey
	remote  *remoteJWKSSource
}

type jwtKey struct {
	kid    string
	alg    string
	secret []byte
	rsa    *rsa.PublicKey
	ecdsa  *ecdsa.PublicKey
}

func newJWTVerifier(cfg config.APIAuthConfig) (*jwtVerifier, error) {
	verifier := &jwtVerifier{allowed: map[string]struct{}{}}
	for _, alg := range cfg.JWTAlgorithms {
		alg = strings.ToUpper(strings.TrimSpace(alg))
		if alg == "" {
			continue
		}
		if alg == "NONE" {
			return nil, fmt.Errorf("JWT alg none is not allowed")
		}
		if !supportedJWTAlg(alg) {
			return nil, fmt.Errorf("unsupported JWT alg %q", alg)
		}
		verifier.allowed[alg] = struct{}{}
	}
	if secret := cfg.JWTSharedSecret; strings.TrimSpace(secret) != "" {
		verifier.keys = append(verifier.keys, jwtKey{secret: []byte(secret)})
	}
	if pemText := strings.TrimSpace(cfg.JWTPublicKeyPEM); pemText != "" {
		keys, err := publicKeysFromPEM([]byte(pemText))
		if err != nil {
			return nil, err
		}
		verifier.keys = append(verifier.keys, keys...)
	}
	if path := strings.TrimSpace(cfg.JWTPublicKeyFile); path != "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read JWT public key file: %w", err)
		}
		keys, err := publicKeysFromPEM(contents)
		if err != nil {
			return nil, err
		}
		verifier.keys = append(verifier.keys, keys...)
	}
	if raw := strings.TrimSpace(cfg.JWKSJSON); raw != "" {
		keys, err := publicKeysFromJWKS([]byte(raw))
		if err != nil {
			return nil, err
		}
		verifier.keys = append(verifier.keys, keys...)
	}
	if path := strings.TrimSpace(cfg.JWKSFile); path != "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read JWKS file: %w", err)
		}
		keys, err := publicKeysFromJWKS(contents)
		if err != nil {
			return nil, err
		}
		verifier.keys = append(verifier.keys, keys...)
	}
	if strings.TrimSpace(cfg.JWKSURL) != "" || strings.TrimSpace(cfg.JWKSCacheFile) != "" {
		remote, err := newRemoteJWKSSource(cfg)
		if err != nil {
			return nil, err
		}
		if err := remote.LoadCache(); err != nil && strings.TrimSpace(cfg.JWKSURL) == "" {
			return nil, err
		}
		if remote.HasURL() {
			if err := remote.RefreshOnce(); err != nil && len(verifier.keys) == 0 && !remote.HasKeys() {
				return nil, err
			}
		}
		verifier.remote = remote
	}
	if len(verifier.allowed) > 0 && len(verifier.snapshotKeys()) == 0 {
		return nil, fmt.Errorf("JWT algorithms require at least one verification key")
	}
	if verifier.remote != nil {
		verifier.remote.Start()
	}
	return verifier, nil
}

func (v *jwtVerifier) configured() bool {
	return v != nil && (len(v.keys) > 0 || v.remote != nil)
}

func (v *jwtVerifier) Close() {
	if v != nil && v.remote != nil {
		v.remote.Close()
	}
}

func (v *jwtVerifier) snapshotKeys() []jwtKey {
	if v == nil {
		return nil
	}
	keys := append([]jwtKey(nil), v.keys...)
	if v.remote != nil {
		keys = append(keys, v.remote.Keys()...)
	}
	return keys
}

func (v *jwtVerifier) Verify(token parsedJWT) error {
	if !v.configured() {
		return nil
	}
	if token.alg == "" || strings.EqualFold(token.alg, "none") {
		return fmt.Errorf("unsigned JWT is not allowed")
	}
	if len(v.allowed) > 0 {
		if _, ok := v.allowed[token.alg]; !ok {
			return fmt.Errorf("JWT alg %q is not allowed", token.alg)
		}
	}
	keys := v.snapshotKeys()
	if len(keys) == 0 {
		return fmt.Errorf("no JWT verification keys are loaded")
	}
	var sawCandidate bool
	for _, key := range keys {
		if token.kid != "" && key.kid != "" && token.kid != key.kid {
			continue
		}
		if key.alg != "" && token.alg != key.alg {
			continue
		}
		if !keySupportsAlg(key, token.alg) {
			continue
		}
		sawCandidate = true
		if verifyJWTSignature(key, token.alg, token.signingInput, token.signature) == nil {
			return nil
		}
	}
	if !sawCandidate {
		return fmt.Errorf("no matching JWT verification key for alg %q kid %q", token.alg, token.kid)
	}
	return fmt.Errorf("JWT signature verification failed")
}

func parseJWT(token string) (parsedJWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return parsedJWT{}, fmt.Errorf("invalid JWT segment count")
	}
	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return parsedJWT{}, err
	}
	payloadBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return parsedJWT{}, err
	}
	signature, err := decodeJWTPart(parts[2])
	if err != nil && parts[2] != "" {
		return parsedJWT{}, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return parsedJWT{}, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return parsedJWT{}, err
	}
	alg, _ := stringClaim(header["alg"])
	kid, _ := stringClaim(header["kid"])
	return parsedJWT{
		header:       header,
		claims:       claims,
		alg:          strings.ToUpper(strings.TrimSpace(alg)),
		kid:          kid,
		signingInput: []byte(parts[0] + "." + parts[1]),
		signature:    signature,
	}, nil
}

func parseJWTClaims(token string) (map[string]any, error) {
	parsed, err := parseJWT(token)
	if err != nil {
		return nil, err
	}
	return parsed.claims, nil
}

func decodeJWTPart(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func supportedJWTAlg(alg string) bool {
	switch alg {
	case "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

func keySupportsAlg(key jwtKey, alg string) bool {
	switch {
	case strings.HasPrefix(alg, "HS"):
		return len(key.secret) > 0
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return key.rsa != nil
	case strings.HasPrefix(alg, "ES"):
		if key.ecdsa == nil {
			return false
		}
		switch alg {
		case "ES256":
			return key.ecdsa.Curve == elliptic.P256()
		case "ES384":
			return key.ecdsa.Curve == elliptic.P384()
		case "ES512":
			return key.ecdsa.Curve == elliptic.P521()
		default:
			return false
		}
	default:
		return false
	}
}

func verifyJWTSignature(key jwtKey, alg string, signingInput, signature []byte) error {
	hash, digest, err := jwtDigest(alg, signingInput)
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(alg, "HS"):
		mac := hmac.New(hash.New, key.secret)
		_, _ = mac.Write(signingInput)
		if !hmac.Equal(mac.Sum(nil), signature) {
			return fmt.Errorf("HMAC mismatch")
		}
		return nil
	case strings.HasPrefix(alg, "RS"):
		return rsa.VerifyPKCS1v15(key.rsa, hash, digest, signature)
	case strings.HasPrefix(alg, "PS"):
		return rsa.VerifyPSS(key.rsa, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case strings.HasPrefix(alg, "ES"):
		size := ecdsaSignatureSize(alg)
		if size == 0 || len(signature) != size*2 {
			return fmt.Errorf("invalid ECDSA signature size")
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(key.ecdsa, digest, r, s) {
			return fmt.Errorf("ECDSA signature mismatch")
		}
		return nil
	default:
		return fmt.Errorf("unsupported JWT alg %q", alg)
	}
}

func jwtDigest(alg string, input []byte) (crypto.Hash, []byte, error) {
	switch {
	case strings.HasSuffix(alg, "256"):
		sum := sha256.Sum256(input)
		return crypto.SHA256, sum[:], nil
	case strings.HasSuffix(alg, "384"):
		sum := sha512.Sum384(input)
		return crypto.SHA384, sum[:], nil
	case strings.HasSuffix(alg, "512"):
		sum := sha512.Sum512(input)
		return crypto.SHA512, sum[:], nil
	default:
		return 0, nil, fmt.Errorf("unsupported JWT alg %q", alg)
	}
}

func ecdsaSignatureSize(alg string) int {
	switch alg {
	case "ES256":
		return 32
	case "ES384":
		return 48
	case "ES512":
		return 66
	default:
		return 0
	}
}

func publicKeysFromPEM(contents []byte) ([]jwtKey, error) {
	var keys []jwtKey
	rest := contents
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		switch block.Type {
		case "PUBLIC KEY":
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			parsed, err := jwtKeyFromPublicKey(key)
			if err != nil {
				return nil, err
			}
			keys = append(keys, parsed)
		case "RSA PUBLIC KEY":
			key, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			keys = append(keys, jwtKey{rsa: key})
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			parsed, err := jwtKeyFromPublicKey(cert.PublicKey)
			if err != nil {
				return nil, err
			}
			keys = append(keys, parsed)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no supported public keys found in PEM")
	}
	return keys, nil
}

func jwtKeyFromPublicKey(key any) (jwtKey, error) {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		return jwtKey{rsa: typed}, nil
	case *ecdsa.PublicKey:
		return jwtKey{ecdsa: typed}, nil
	default:
		return jwtKey{}, fmt.Errorf("unsupported JWT public key type %T", key)
	}
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	K   string `json:"k"`
}

func publicKeysFromJWKS(contents []byte) ([]jwtKey, error) {
	var doc jwksDocument
	if err := json.Unmarshal(contents, &doc); err != nil {
		return singleJWK(contents, err)
	}
	if len(doc.Keys) == 0 {
		if keys, err := singleJWK(contents, nil); err == nil {
			return keys, nil
		}
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no keys")
	}
	var keys []jwtKey
	for _, raw := range doc.Keys {
		if strings.EqualFold(raw.Use, "enc") {
			continue
		}
		key, err := jwtKeyFromJWK(raw)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no supported signing keys")
	}
	return keys, nil
}

func singleJWK(contents []byte, fallback error) ([]jwtKey, error) {
	var single jwkKey
	if err := json.Unmarshal(contents, &single); err != nil {
		if fallback != nil {
			return nil, fallback
		}
		return nil, err
	}
	key, err := jwtKeyFromJWK(single)
	if err != nil {
		return nil, err
	}
	return []jwtKey{key}, nil
}

func jwtKeyFromJWK(raw jwkKey) (jwtKey, error) {
	key := jwtKey{kid: raw.Kid, alg: strings.ToUpper(strings.TrimSpace(raw.Alg))}
	switch strings.ToUpper(strings.TrimSpace(raw.Kty)) {
	case "RSA":
		nBytes, err := decodeJWTPart(raw.N)
		if err != nil {
			return jwtKey{}, err
		}
		eBytes, err := decodeJWTPart(raw.E)
		if err != nil {
			return jwtKey{}, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		if e == 0 {
			return jwtKey{}, fmt.Errorf("invalid RSA exponent in JWK")
		}
		key.rsa = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
		return key, nil
	case "EC":
		xBytes, err := decodeJWTPart(raw.X)
		if err != nil {
			return jwtKey{}, err
		}
		yBytes, err := decodeJWTPart(raw.Y)
		if err != nil {
			return jwtKey{}, err
		}
		curve := curveForJWK(raw.Crv)
		if curve == nil {
			return jwtKey{}, fmt.Errorf("unsupported EC curve %q", raw.Crv)
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		if !curve.IsOnCurve(x, y) {
			return jwtKey{}, fmt.Errorf("EC JWK point is not on curve")
		}
		key.ecdsa = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		return key, nil
	case "OCT":
		secret, err := decodeJWTPart(raw.K)
		if err != nil {
			return jwtKey{}, err
		}
		key.secret = secret
		return key, nil
	default:
		return jwtKey{}, fmt.Errorf("unsupported JWK kty %q", raw.Kty)
	}
}

func curveForJWK(crv string) elliptic.Curve {
	switch strings.ToUpper(strings.TrimSpace(crv)) {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}
