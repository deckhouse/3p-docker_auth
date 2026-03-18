/*
   Copyright 2015 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/docker/libtrust"
	yaml "gopkg.in/yaml.v2"

	"github.com/cesanta/docker_auth/auth_server/authn"
	"github.com/cesanta/docker_auth/auth_server/authz"
	"github.com/cesanta/docker_auth/auth_server/k8s"
)

type Config struct {
	Server         ServerConfig                   `yaml:"server"`
	Token          TokenConfig                    `yaml:"token"`
	Users          map[string]*authn.Requirements `yaml:"users,omitempty"`
	KubernetesAuth *k8s.AuthConfig                `yaml:"kubernetes_auth,omitempty"`
	PluginAuthn    *authn.PluginAuthnConfig       `yaml:"plugin_authn,omitempty"`
	ACL            authz.ACL                      `yaml:"acl,omitempty"`
	PluginAuthz    *authz.PluginAuthzConfig       `yaml:"plugin_authz,omitempty"`
	CasbinAuthz    *authz.CasbinAuthzConfig       `yaml:"casbin_authz,omitempty"`
}

type ServerConfig struct {
	ListenAddress       string            `yaml:"addr,omitempty"`
	Net                 string            `yaml:"net,omitempty"`
	PathPrefix          string            `yaml:"path_prefix,omitempty"`
	RealIPHeader        string            `yaml:"real_ip_header,omitempty"`
	RealIPPos           int               `yaml:"real_ip_pos,omitempty"`
	CertFile            string            `yaml:"certificate,omitempty"`
	KeyFile             string            `yaml:"key,omitempty"`
	HSTS                bool              `yaml:"hsts,omitempty"`
	TLSMinVersion       string            `yaml:"tls_min_version,omitempty"`
	TLSCurvePreferences []string          `yaml:"tls_curve_preferences,omitempty"`
	TLSCipherSuites     []string          `yaml:"tls_cipher_suites,omitempty"`

	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
	sigAlg     string
}

type TokenConfig struct {
	Issuer             string `yaml:"issuer,omitempty"`
	CertFile           string `yaml:"certificate,omitempty"`
	KeyFile            string `yaml:"key,omitempty"`
	Expiration         int64  `yaml:"expiration,omitempty"`
	DisableLegacyKeyID bool   `yaml:"disable_legacy_key_id,omitempty"`

	publicKey  libtrust.PublicKey
	privateKey libtrust.PrivateKey
	sigAlg     string
	keyID      string
}

// TLSCipherSuitesValues maps CipherSuite names as strings to the actual values
// in the crypto/tls package
// Taken from https://golang.org/pkg/crypto/tls/#pkg-constants
var TLSCipherSuitesValues = map[string]uint16{
	// TLS 1.0 - 1.2 cipher suites.
	"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	// TLS 1.3 cipher suites.
	"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
	"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	"TLS_FALLBACK_SCSV": tls.TLS_FALLBACK_SCSV,
}

// TLSVersionValues maps Version names as strings to the actual values in the
// crypto/tls package
// Taken from https://golang.org/pkg/crypto/tls/#pkg-constants
var TLSVersionValues = map[string]uint16{
	"TLS10": tls.VersionTLS10,
	"TLS11": tls.VersionTLS11,
	"TLS12": tls.VersionTLS12,
	"TLS13": tls.VersionTLS13,
	// Deprecated: SSLv3 is cryptographically broken, and will be
	// removed in Go 1.14. See golang.org/issue/32716.
	"SSL30": tls.VersionSSL30,
}

// TLSCurveIDValues maps CurveID names as strings to the actual values in the
// crypto/tls package
// Taken from https://golang.org/pkg/crypto/tls/#CurveID
var TLSCurveIDValues = map[string]tls.CurveID{
	"P256":   tls.CurveP256,
	"P384":   tls.CurveP384,
	"P521":   tls.CurveP521,
	"X25519": tls.X25519,
}

func validate(c *Config) error {
	if c.Server.ListenAddress == "" {
		return errors.New("server.addr is required")
	}
	if c.Server.Net != "unix" && c.Server.Net != "tcp" {
		if c.Server.Net == "" {
			c.Server.Net = "tcp"
		} else {
			return errors.New("server.net must be unix or tcp")
		}
	}
	if c.Server.PathPrefix != "" && !strings.HasPrefix(c.Server.PathPrefix, "/") {
		return errors.New("server.path_prefix must be an absolute path")
	}
	if (c.Server.TLSMinVersion == "0x0304" || c.Server.TLSMinVersion == "TLS13") && c.Server.TLSCipherSuites != nil {
		return errors.New("TLS 1.3 ciphersuites are not configurable")
	}
	if c.Token.Issuer == "" {
		return errors.New("token.issuer is required")
	}
	if c.Token.Expiration <= 0 {
		return fmt.Errorf("expiration must be positive, got %d", c.Token.Expiration)
	}
	if c.Users == nil && c.PluginAuthn == nil && c.KubernetesAuth == nil {
		return errors.New("no auth methods are configured, this is probably a mistake. Use an empty user map if you really want to deny everyone")
	}
	if c.KubernetesAuth != nil {
		k8s.ApplyDefaults(c.KubernetesAuth)
		if err := c.KubernetesAuth.Validate("kubernetes_auth"); err != nil {
			return err
		}
	}
	hasK8sAuthz := c.KubernetesAuth != nil && c.KubernetesAuth.Authz != nil
	if c.ACL == nil && c.PluginAuthz == nil && c.CasbinAuthz == nil && !hasK8sAuthz {
		return errors.New("ACL is empty, this is probably a mistake. Use an empty list if you really want to deny all actions")
	}

	if c.ACL != nil {
		if err := authz.ValidateACL(c.ACL); err != nil {
			return fmt.Errorf("invalid ACL: %s", err)
		}
	}
	if c.PluginAuthn != nil {
		if err := c.PluginAuthn.Validate(); err != nil {
			return fmt.Errorf("bad plugin_authn config: %s", err)
		}
	}
	if c.PluginAuthz != nil {
		if err := c.PluginAuthz.Validate(); err != nil {
			return fmt.Errorf("bad plugin_authz config: %s", err)
		}
	}
	return nil
}

func loadCertAndKey(certFile string, keyFile string) (pk libtrust.PublicKey, prk libtrust.PrivateKey, sigAlg string, err error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	pk, err = libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return
	}
	prk, err = libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	_, sigAlg, errStr := prk.Sign(strings.NewReader("dummy"), 0)
	if errStr != nil {
		err = fmt.Errorf("failed to sign: %s", errStr)
		return
	}
	return
}

func LoadConfig(fileName string) (*Config, error) {
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %s", fileName, err)
	}
	c := &Config{}
	if err = yaml.Unmarshal(contents, c); err != nil {
		return nil, fmt.Errorf("could not parse config: %s", err)
	}
	if err = validate(c); err != nil {
		return nil, fmt.Errorf("invalid config: %s", err)
	}
	serverConfigured := false
	if c.Server.CertFile != "" || c.Server.KeyFile != "" {
		// Check for partial configuration.
		if c.Server.CertFile == "" || c.Server.KeyFile == "" {
			return nil, fmt.Errorf("failed to load server cert and key: both were not provided")
		}
		c.Server.publicKey, c.Server.privateKey, c.Server.sigAlg, err = loadCertAndKey(c.Server.CertFile, c.Server.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server cert and key: %s", err)
		}
		serverConfigured = true
	}
	tokenConfigured := false
	if c.Token.CertFile != "" || c.Token.KeyFile != "" {
		// Check for partial configuration.
		if c.Token.CertFile == "" || c.Token.KeyFile == "" {
			return nil, fmt.Errorf("failed to load token cert and key: both were not provided")
		}
		c.Token.publicKey, c.Token.privateKey, c.Token.sigAlg, err = loadCertAndKey(c.Token.CertFile, c.Token.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load token cert and key: %s", err)
		}
		tokenConfigured = true
	}

	if serverConfigured && !tokenConfigured {
		c.Token.publicKey, c.Token.privateKey, c.Token.sigAlg = c.Server.publicKey, c.Server.privateKey, c.Server.sigAlg
		tokenConfigured = true
	}

	if !tokenConfigured {
		return nil, fmt.Errorf("failed to load token cert and key: none provided")
	}

	if c.Token.DisableLegacyKeyID {
		c.Token.keyID = getRFC7638Thumbprint(c.Token.publicKey.CryptoPublicKey())
	} else {
		c.Token.keyID = c.Token.publicKey.KeyID()
	}

	return c, nil
}

// getRFC7638Thumbprint will generate the JWK thumbprint (https://www.rfc-editor.org/rfc/rfc7638.html) for a crypto.PublicKey.
//
// Copied from https://github.com/distribution/distribution/blob/51bdcb7bac069f263ce238db6bd0610759c2635f/registry/auth/token/util.go#L63
func getRFC7638Thumbprint(publickey crypto.PublicKey) string {
	var payload string

	switch pubkey := publickey.(type) {
	case *rsa.PublicKey:
		e_big := big.NewInt(int64(pubkey.E)).Bytes()

		e := base64.RawURLEncoding.EncodeToString(e_big)
		n := base64.RawURLEncoding.EncodeToString(pubkey.N.Bytes())

		payload = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)
	case *ecdsa.PublicKey:
		params := pubkey.Params()
		crv := params.Name
		x := base64.RawURLEncoding.EncodeToString(params.Gx.Bytes())
		y := base64.RawURLEncoding.EncodeToString(params.Gy.Bytes())

		payload = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, crv, x, y)
	default:
		return ""
	}

	shasum := sha256.Sum256([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(shasum[:])
}
