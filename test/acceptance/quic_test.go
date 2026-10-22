package acceptance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Advertise the certified public key while deliberately signing with another
// private key. A trusted certificate chain must not substitute for TLS proof
// of possession of the corresponding client key.
type wrongCertificateSigner struct {
	crypto.Signer
	public crypto.PublicKey
}

func (s wrongCertificateSigner) Public() crypto.PublicKey { return s.public }

func withQUIC(config map[string]any) {
	resources := config["static_resources"].(map[string]any)
	listeners := resources["listeners"].([]any)
	data, _ := json.Marshal(listeners[0])
	var listener map[string]any
	_ = json.Unmarshal(data, &listener)
	listener["name"] = "quic"
	listener["address"].(map[string]any)["socket_address"].(map[string]any)["protocol"] = "UDP"
	listener["udp_listener_config"] = map[string]any{"quic_options": map[string]any{"crypto_handshake_timeout": "3s"}}
	chain := listener["filter_chains"].([]any)[0].(map[string]any)
	delete(chain, "transport_socket_connect_timeout")
	tlsContext := chain["transport_socket"].(map[string]any)["typed_config"].(map[string]any)
	delete(tlsContext, "@type")
	common := tlsContext["common_tls_context"].(map[string]any)
	common["alpn_protocols"] = []any{"h3"}
	common["tls_params"].(map[string]any)["tls_minimum_protocol_version"] = "TLSv1_3"
	chain["transport_socket"] = map[string]any{"name": "envoy.transport_sockets.quic", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.transport_sockets.quic.v3.QuicDownstreamTransport", "downstream_tls_context": tlsContext, "enable_early_data": false}}
	hcm := chain["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
	hcm["codec_type"] = "HTTP3"
	hcm["stat_prefix"] = "quic"
	hcm["http3_protocol_options"] = map[string]any{"quic_protocol_options": map[string]any{"connection_keepalive": map[string]any{"initial_interval": "1s", "max_interval": "1s"}}}
	delete(hcm, "http2_protocol_options")
	resources["listeners"] = append(listeners, listener)
}
func quicValidation(config map[string]any) map[string]any {
	for _, v := range config["static_resources"].(map[string]any)["listeners"].([]any) {
		l := v.(map[string]any)
		if l["name"] == "quic" {
			return l["filter_chains"].([]any)[0].(map[string]any)["transport_socket"].(map[string]any)["typed_config"].(map[string]any)["downstream_tls_context"].(map[string]any)["common_tls_context"].(map[string]any)["validation_context"].(map[string]any)
		}
	}
	panic("QUIC listener missing")
}
func (g *gateway) quicClient(t *testing.T, tc *tls.Config) *http.Client {
	t.Helper()
	tr := &http3.Transport{TLSClientConfig: tc, QUICConfig: &quic.Config{MaxIdleTimeout: 5 * time.Second, HandshakeIdleTimeout: 2 * time.Second, KeepAlivePeriod: time.Second}}
	tr.Dial = func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
		return quic.DialAddr(ctx, g.quicAddr, tc, qc)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return &http.Client{Transport: tr, Timeout: 6 * time.Second}
}
func TestQUICClientAuthenticationAndContinuousAuthorization(t *testing.T) {
	g := newGateway(t, withQUIC)
	client := g.quicClient(t, g.tls.Clone())
	t.Run("validated-identity-and-multiplexing", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for range 4 {
			wg.Go(func() {
				r, e := client.Get("https://localhost/")
				if e != nil {
					errs <- e
					return
				}
				defer r.Body.Close()
				data, e := io.ReadAll(r.Body)
				if e != nil {
					errs <- e
					return
				}
				if r.ProtoMajor != 3 || r.StatusCode != 200 || string(data) != "ok" {
					errs <- fmt.Errorf("%s status%d %s", r.Proto, r.StatusCode, data)
				}
			})
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Error(e)
		}
	})
	t.Run("missing-client-certificate", func(t *testing.T) {
		tc := g.tls.Clone()
		tc.Certificates = nil
		r, e := g.quicClient(t, tc).Get("https://localhost/")
		if e == nil {
			r.Body.Close()
			t.Fatalf("no certificate reached HTTP %d", r.StatusCode)
		}
	})
	t.Run("foreign-ca", func(t *testing.T) {
		foreign, _, _, _ := testPKI(t, t.TempDir())
		tc := g.tls.Clone()
		tc.Certificates = foreign.Certificates
		r, e := g.quicClient(t, tc).Get("https://localhost/")
		if e == nil {
			r.Body.Close()
			t.Fatalf("untrusted certificate reached HTTP %d", r.StatusCode)
		}
	})
	t.Run("trusted-chain-with-invalid-private-key-proof", func(t *testing.T) {
		original := g.tls.Certificates[0].PrivateKey.(crypto.Signer)
		wrong, err := ecdsa.GenerateKey(original.Public().(*ecdsa.PublicKey).Curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tc := g.tls.Clone()
		tc.Certificates = append([]tls.Certificate(nil), tc.Certificates...)
		tc.Certificates[0].PrivateKey = wrongCertificateSigner{Signer: wrong, public: original.Public()}
		r, err := g.quicClient(t, tc).Get("https://localhost/")
		if err == nil {
			r.Body.Close()
			t.Fatalf("invalid client CertificateVerify reached HTTP %d", r.StatusCode)
		}
	})
	for name, serial := range map[string]int{"expired": 4, "server-only-eku": 5, "not-yet-valid": 6} {
		t.Run(name, func(t *testing.T) {
			cert, e := tls.LoadX509KeyPair(filepath.Join(g.pkiDir, fmt.Sprintf("cert-%d.pem", serial)), filepath.Join(g.pkiDir, fmt.Sprintf("key-%d.pem", serial)))
			if e != nil {
				t.Fatal(e)
			}
			tc := g.tls.Clone()
			tc.Certificates = []tls.Certificate{cert}
			r, e := g.quicClient(t, tc).Get("https://localhost/")
			if e == nil {
				r.Body.Close()
				t.Fatalf("invalid certificate reached HTTP %d", r.StatusCode)
			}
		})
	}

	t.Run("resource-bound-stream-isolation", func(t *testing.T) {
		allowed := g.request(t, client, "/silent-sse", "allowed.example")
		revoked := g.request(t, client, "/silent-sse", "revoked.example")
		defer func() {
			allowed.Body.Close()
			revoked.Body.Close()
			waitForActiveUpstreams(t, &g.activeSSE, 0, "QUIC isolated streams cleanup")
		}()
		initial := []byte("data: initial\n\n")
		for _, response := range []*http.Response{allowed, revoked} {
			if response.StatusCode != 200 || response.ProtoMajor != 3 {
				t.Fatalf("%s %s", response.Proto, response.Status)
			}
			if _, err := io.ReadFull(response.Body, make([]byte, len(initial))); err != nil {
				t.Fatal(err)
			}
		}
		g.policy.set("revoked.example", true)
		defer g.policy.set("revoked.example", false)
		done := make(chan error, 1)
		go func() { _, err := revoked.Body.Read(make([]byte, 1)); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("revoked stream returned data")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("bound QUIC stream stayed open")
		}
		waitForActiveUpstreams(t, &g.activeSSE, 1, "allowed QUIC stream preserved")
		for host, want := range map[string]int{"allowed.example": 200, "revoked.example": 403} {
			response := g.request(t, client, "/", host)
			response.Body.Close()
			if response.ProtoMajor != 3 || response.StatusCode != want {
				t.Fatalf("%s: %s %s", host, response.Proto, response.Status)
			}
		}
	})
	t.Run("quiet-stream-revoked-upstream-cancelled", func(t *testing.T) {
		r, e := client.Get("https://localhost/silent-sse")
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		if r.ProtoMajor != 3 || r.StatusCode != 200 {
			t.Fatalf("%s %s", r.Proto, r.Status)
		}
		initial := make([]byte, len("data: initial\n\n"))
		if _, e = io.ReadFull(r.Body, initial); e != nil {
			t.Fatal(e)
		}
		g.policy.set("fixture.default", true)
		defer g.policy.set("fixture.default", false)
		done := make(chan error, 1)
		go func() { _, e := r.Body.Read(make([]byte, 1)); done <- e }()
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("revoked stream returned data")
			}
		case <-time.After(4 * time.Second):
			t.Fatal("revoked HTTP/3 stream remains open")
		}
		waitForActiveUpstreams(t, &g.activeSSE, 0, "HTTP/3 SSE")
		r2, e := client.Get("https://localhost/")
		if e != nil {
			t.Fatal(e)
		}
		defer r2.Body.Close()
		if r2.StatusCode != 403 {
			t.Fatalf("revoked access HTTP%d", r2.StatusCode)
		}
	})
	t.Run("authorization-outage-closes-stream", func(t *testing.T) {
		r, e := client.Get("https://localhost/silent-sse")
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		b := make([]byte, len("data: initial\n\n"))
		if _, e = io.ReadFull(r.Body, b); e != nil {
			t.Fatal(e)
		}
		g.policy.outage(true)
		defer g.policy.outage(false)
		if _, e = r.Body.Read(make([]byte, 1)); e == nil {
			t.Fatal("stream continued during authorization outage")
		}
	})
	t.Run("resumption-requires-fresh-identity", func(t *testing.T) {
		tc := g.tls.Clone()
		tc.ClientSessionCache = tls.NewLRUClientSessionCache(4)
		for range 2 {
			r, e := g.quicClient(t, tc).Get("https://localhost/")
			if e != nil {
				t.Fatal(e)
			}
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.TLS == nil || r.TLS.DidResume {
				t.Fatal("QUIC resumed client authentication")
			}
		}
		tc.Certificates = nil
		r, e := g.quicClient(t, tc).Get("https://localhost/")
		if e == nil {
			r.Body.Close()
			t.Fatal("cached session accepted without certificate")
		}
	})
}
func TestQUICUsesConfiguredCertificateValidator(t *testing.T) {
	for _, name := range []string{"fingerprint", "san", "crl"} {
		t.Run(name, func(t *testing.T) {
			g := newGateway(t, withQUIC, func(c map[string]any) {
				v := quicValidation(c)
				switch name {
				case "fingerprint":
					v["verify_certificate_hash"] = []string{strings.Repeat("00", 32)}
				case "san":
					v["match_typed_subject_alt_names"] = []any{map[string]any{"san_type": "DNS", "matcher": map[string]any{"exact": "forbidden.example"}}}
				case "crl":
					v["crl"] = map[string]any{"filename": "/test/revoked.crl"}
				}
			})
			r, e := g.quicClient(t, g.tls.Clone()).Get("https://localhost/")
			if e == nil {
				r.Body.Close()
				t.Fatalf("%s validation bypassed HTTP%d", name, r.StatusCode)
			}
		})
	}
}

func TestQUICServerKeepaliveProtectsQuietSession(t *testing.T) {
	g := newGateway(t, withQUIC, func(c map[string]any) {
		for _, value := range c["static_resources"].(map[string]any)["listeners"].([]any) {
			listener := value.(map[string]any)
			if listener["name"] == "quic" {
				listener["udp_listener_config"].(map[string]any)["quic_options"].(map[string]any)["idle_timeout"] = "2s"
			}
		}
	})
	transport := &http3.Transport{TLSClientConfig: g.tls.Clone(), QUICConfig: &quic.Config{MaxIdleTimeout: 2 * time.Second}}
	transport.Dial = func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
		return quic.DialAddr(ctx, g.quicAddr, tc, qc)
	}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	response, err := client.Get("https://localhost/silent-sse")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 3 || response.StatusCode != 200 {
		t.Fatal(response.Status)
	}
	initial := make([]byte, len("data: initial\n\n"))
	if _, err = io.ReadFull(response.Body, initial); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := response.Body.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("quiet session closed before policy change: %v", err)
	case <-time.After(3500 * time.Millisecond):
	}
	g.policy.set("fixture.default", true)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked session returned data")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("quiet session survived denial")
	}
	waitForActiveUpstreams(t, &g.activeSSE, 0, "quiet HTTP/3 keepalive")
}
