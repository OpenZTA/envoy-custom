package acceptance

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	wt "github.com/quic-go/webtransport-go"
)

func TestWebTransportNativeSessionLifecycle(t *testing.T) {
	if os.Getenv("OPENZTA_ENVOY_IMAGE") == "" {
		t.Skip("set OPENZTA_ENVOY_IMAGE to the built native image")
	}
	_, caFile, certFile, keyFile := testPKI(t, t.TempDir())
	certificate, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := os.ReadFile(caFile)
	if e != nil {
		t.Fatal(e)
	}
	socket, e := net.ListenPacket("udp", fixtureListenAddress())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = socket.Close() })
	var accepted, active, children atomic.Int64
	streamFailures := make(chan error, 32)
	var backendTLS atomic.Pointer[tls.Config]
	server := &wt.Server{H3: &http3.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cfg := backendTLS.Load()
		if cfg == nil {
			return nil, fmt.Errorf("backend trust is not initialized")
		}
		return cfg, nil
	}}, QUICConfig: &quic.Config{MaxIncomingStreams: 3, MaxIncomingUniStreams: 4, MaxStreamReceiveWindow: 256 << 10, MaxConnectionReceiveWindow: 4 << 20}}, CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "https://localhost" }}
	server.H3.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wt" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-OpenZTA-Session-ID") == "" || r.Header.Get("X-Original-Method") != "CONNECT" {
			http.Error(w, "no bound policy session", 403)
			return
		}
		sess, e := server.Upgrade(w, r)
		if e != nil {
			return
		}
		accepted.Add(1)
		active.Add(1)
		defer active.Add(-1)
		defer sess.CloseWithError(0, "done")
		if r.URL.Query().Get("close") == "backend" {
			// Simulate a resource revoking an application session independently of
			// the proxy's NAC check. QUICHE consumes the close capsule and FIN.
			timer := time.AfterFunc(100*time.Millisecond, func() {
				_ = sess.CloseWithError(0x4321, "application access revoked")
			})
			defer timer.Stop()
		}
		go func() {
			for {
				stream, e := sess.AcceptStream(sess.Context())
				if e != nil {
					return
				}
				children.Add(1)
				go func() {
					defer children.Add(-1)
					defer stream.Close()
					defer stream.CancelRead(0)
					if _, err := io.CopyBuffer(stream, stream, make([]byte, 16384)); err != nil {
						select {
						case streamFailures <- err:
						default:
						}
					}
				}()
			}
		}()
		go func() {
			for {
				stream, e := sess.AcceptUniStream(sess.Context())
				if e != nil {
					return
				}
				children.Add(1)
				go func() {
					defer children.Add(-1)
					defer stream.CancelRead(0)
					out, e := sess.OpenUniStreamSync(sess.Context())
					if e != nil {
						return
					}
					defer out.Close()
					_, _ = io.CopyBuffer(out, stream, make([]byte, 16384))
				}()
			}
		}()
		go func() {
			for {
				packet, e := sess.ReceiveDatagram(sess.Context())
				if e != nil {
					return
				}
				_ = sess.SendDatagram(packet)
			}
		}()
		<-sess.Context().Done()
	})
	go server.Serve(socket)
	t.Cleanup(func() { _ = server.Close() })
	// A plain HTTP/3 backend that returns 200 without WebTransport SETTINGS must
	// never create a successful downstream WebTransport session.
	plainSocket, e := net.ListenPacket("udp", fixtureListenAddress())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = plainSocket.Close() })
	var bareResponses atomic.Int64
	plain := &http3.Server{TLSConfig: server.H3.TLSConfig.Clone(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bareResponses.Add(1)
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	})}
	go plain.Serve(plainSocket)
	t.Cleanup(func() { _ = plain.Close() })
	g := newGateway(t, withQUIC, func(config map[string]any) {
		config["layered_runtime"].(map[string]any)["layers"].([]any)[0].(map[string]any)["static_layer"].(map[string]any)["envoy.reloadable_features.quic_support_web_transport"] = true
		resources := config["static_resources"].(map[string]any)
		// Clone the existing DNS endpoint and replace only its protocol and TLS.
		data, _ := json.Marshal(resources["clusters"].([]any)[2])
		var c map[string]any
		_ = json.Unmarshal(data, &c)
		c["name"] = "wt"
		assignment := c["load_assignment"].(map[string]any)
		assignment["cluster_name"] = "wt"
		assignment["endpoints"].([]any)[0].(map[string]any)["lb_endpoints"].([]any)[0].(map[string]any)["endpoint"].(map[string]any)["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = socket.LocalAddr().(*net.UDPAddr).Port
		c["typed_extension_protocol_options"] = map[string]any{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions", "common_http_protocol_options": map[string]any{"max_requests_per_connection": 1}, "explicit_http_config": map[string]any{"http3_protocol_options": map[string]any{"allow_extended_connect": true}}}}
		c["transport_socket"] = map[string]any{"name": "envoy.transport_sockets.quic", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.transport_sockets.quic.v3.QuicUpstreamTransport", "upstream_tls_context": map[string]any{"sni": "localhost", "common_tls_context": map[string]any{"alpn_protocols": []any{"h3"}, "validation_context": map[string]any{"trusted_ca": map[string]any{"inline_string": string(ca)}, "match_typed_subject_alt_names": []any{map[string]any{"san_type": "DNS", "matcher": map[string]any{"exact": "localhost"}}}}}}}}
		front := resources["listeners"].([]any)[0].(map[string]any)["filter_chains"].([]any)[0].(map[string]any)["transport_socket"].(map[string]any)["typed_config"].(map[string]any)["common_tls_context"].(map[string]any)
		c["transport_socket"].(map[string]any)["typed_config"].(map[string]any)["upstream_tls_context"].(map[string]any)["common_tls_context"].(map[string]any)["tls_certificates"] = front["tls_certificates"]
		resources["clusters"] = append(resources["clusters"].([]any), c)
		plainData, _ := json.Marshal(c)
		var plainCluster map[string]any
		_ = json.Unmarshal(plainData, &plainCluster)
		plainCluster["name"] = "wt-no-negotiation"
		plainAssignment := plainCluster["load_assignment"].(map[string]any)
		plainAssignment["cluster_name"] = "wt-no-negotiation"
		plainAssignment["endpoints"].([]any)[0].(map[string]any)["lb_endpoints"].([]any)[0].(map[string]any)["endpoint"].(map[string]any)["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = plainSocket.LocalAddr().(*net.UDPAddr).Port
		resources["clusters"] = append(resources["clusters"].([]any), plainCluster)

		for _, value := range resources["listeners"].([]any) {
			l := value.(map[string]any)
			if l["name"] != "quic" {
				continue
			}
			h := l["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
			h["http3_protocol_options"].(map[string]any)["allow_extended_connect"] = true
			h["http_filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)["authorization"].(map[string]any)["status_on_error"] = map[string]any{"code": "ServiceUnavailable"}
			upgrades := []any{map[string]any{"upgrade_type": "webtransport"}, map[string]any{"upgrade_type": "webtransport-h3"}}
			h["upgrade_configs"] = upgrades
			v := h["route_config"].(map[string]any)["virtual_hosts"].([]any)[0].(map[string]any)
			v["routes"] = append([]any{map[string]any{"match": map[string]any{"path": "/wt"}, "route": map[string]any{"cluster": "wt", "timeout": "0s", "idle_timeout": "0s", "host_rewrite_literal": "localhost", "upgrade_configs": upgrades}}}, v["routes"].([]any)...)
			v["routes"] = append([]any{map[string]any{"match": map[string]any{"path": "/wt-no-negotiation"}, "route": map[string]any{"cluster": "wt-no-negotiation", "timeout": "0s", "idle_timeout": "0s", "host_rewrite_literal": "localhost", "upgrade_configs": upgrades}}}, v["routes"].([]any)...)

		}
	})
	// Require a verified proxy service identity. The downstream user certificate has a
	// different serial and key and must never be forwarded to the private resource.
	gatewayCA, e := os.ReadFile(filepath.Join(g.pkiDir, "ca.pem"))
	if e != nil {
		t.Fatal(e)
	}
	backendRoots := x509.NewCertPool()
	if !backendRoots.AppendCertsFromPEM(gatewayCA) {
		t.Fatal("gateway CA is invalid")
	}
	service, e := tls.LoadX509KeyPair(filepath.Join(g.pkiDir, "cert-2.pem"), filepath.Join(g.pkiDir, "key-2.pem"))
	if e != nil {
		t.Fatal(e)
	}
	backendTLS.Store(&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: backendRoots,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, service.Certificate[0]) {
				return fmt.Errorf("upstream did not present the configured proxy service identity")
			}
			return nil
		}})
	transport := func(tc *tls.Config) *wt.Transport {
		return &wt.Transport{TLSClientConfig: tc, QUICConfig: &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true, MaxIncomingStreams: 64, MaxIncomingUniStreams: 64}, DialAddr: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, g.quicAddr, tc, qc)
		}}
	}
	dial := func(ctx context.Context, tc *tls.Config, path string) (*http.Response, *wt.Session, error) {
		tr := transport(tc)
		r, s, e := tr.Dial(ctx, "https://localhost"+path, http.Header{"Origin": []string{"https://localhost"}})
		t.Cleanup(func() {
			if s != nil {
				_ = s.CloseWithError(0, "cleanup")
			}
			_ = tr.Close()
		})
		return r, s, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	unsupportedCtx, unsupportedCancel := context.WithTimeout(ctx, 10*time.Second)
	_, unsupported, unsupportedErr := dial(unsupportedCtx, g.tls.Clone(), "/wt-no-negotiation")
	unsupportedCancel()
	if unsupportedErr == nil || unsupported != nil || bareResponses.Load() != 1 {
		t.Fatalf("unnegotiated upstream response was not rejected: session=%v err=%v reached=%d", unsupported, unsupportedErr, bareResponses.Load())
	}
	_, sess, e := dial(ctx, g.tls.Clone(), "/wt")
	if e != nil {
		t.Fatal(e)
	}
	for _, size := range []int{0, 1, 256 << 10} {
		stream, e := sess.OpenStreamSync(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
		payload := bytes.Repeat([]byte{0, 255, 128, 42}, size/4)
		if size == 1 {
			payload = []byte{255}
		}
		done := make(chan error, 1)
		go func() {
			_, e := stream.Write(payload)
			if e == nil {
				e = stream.Close()
			}
			done <- e
		}()
		actual, e := io.ReadAll(io.LimitReader(stream, int64(len(payload)+1)))
		if we := <-done; e == nil {
			e = we
		}
		if e != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("bidi %d corruption: %v", size, e)
		}
		stream.CancelRead(0)
	}
	// More simultaneous streams than the upstream QUIC stream limit. Queued streams
	// must resume on MAX_STREAMS rather than hang after the first credit window.
	concurrent := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			child, err := sess.OpenStreamSync(ctx)
			if err != nil {
				concurrent <- err
				return
			}
			defer child.CancelRead(0)
			_ = child.SetDeadline(time.Now().Add(10 * time.Second))
			want := []byte(fmt.Sprintf("concurrent-%d", i))
			if _, err = child.Write(want); err == nil {
				err = child.Close()
			}
			if err == nil {
				var got []byte
				got, err = io.ReadAll(io.LimitReader(child, 64))
				if err == nil && !bytes.Equal(got, want) {
					err = fmt.Errorf("queued stream corruption: %x", got)
				}
			}
			concurrent <- err
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-concurrent; err != nil {
			t.Fatalf("MAX_STREAMS wakeup: %v", err)
		}
	}
	// RESET_STREAM and STOP_SENDING carry application error codes across both
	// QUIC connections. Canceling one child must leave the parent usable.
	waitStreamFailure := func(code wt.StreamErrorCode) {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case err := <-streamFailures:
				var streamError *wt.StreamError
				if errors.As(err, &streamError) && streamError.Remote && streamError.ErrorCode == code {
					return
				}
			case <-deadline.C:
				t.Fatalf("WebTransport child cancellation code %d did not reach backend", code)
			}
		}
	}
	for _, stopSending := range []bool{false, true} {
		child, err := sess.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = child.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err = child.Write([]byte("cancel-ready")); err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(child, make([]byte, len("cancel-ready"))); err != nil {
			t.Fatal(err)
		}
		if stopSending {
			child.CancelRead(0x2345)
			writeDone := make(chan struct{})
			go func() {
				_, _ = child.Write(bytes.Repeat([]byte{42}, 1<<20))
				close(writeDone)
			}()
			waitStreamFailure(0x2345)
			child.CancelWrite(0)
			select {
			case <-writeDone:
			case <-time.After(time.Second):
				t.Fatal("canceled child writer stayed blocked")
			}
		} else {
			child.CancelWrite(0x1234)
			waitStreamFailure(0x1234)
			child.CancelRead(0)
		}
		if sess.Context().Err() != nil {
			t.Fatal("child cancellation closed the WebTransport parent session")
		}
	}
	for i := 0; i < 8; i++ {
		send, err := sess.OpenUniStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte(fmt.Sprintf("uni-%d\x00\xffpayload", i))
		if _, err = send.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = send.Close()
		receive, err := sess.AcceptUniStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := io.ReadAll(io.LimitReader(receive, 64))
		receive.CancelRead(0)
		if err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("UNI MAX_STREAMS iteration %d: %x %v", i, actual, err)
		}
	}
	for _, n := range []int{0, 1, 1000} {
		packet := bytes.Repeat([]byte{byte(n)}, n)
		if e = sess.SendDatagram(packet); e != nil {
			t.Fatal(e)
		}
		actual, e := sess.ReceiveDatagram(ctx)
		if e != nil || !bytes.Equal(actual, packet) {
			t.Fatalf("datagram %d: %x %v", n, actual, e)
		}
	}
	if !t.Run("backend-close-then-downstream-connection-close", func(t *testing.T) {
		for iteration := 0; iteration < 24; iteration++ {
			tr := transport(g.tls.Clone())
			_, parent, err := tr.Dial(ctx, "https://localhost/wt?close=backend", http.Header{"Origin": []string{"https://localhost"}})
			if err != nil {
				_ = tr.Close()
				t.Fatalf("iteration %d: %v", iteration, err)
			}
			select {
			case <-parent.Context().Done():
			case <-time.After(5 * time.Second):
				_ = tr.Close()
				t.Fatal("backend revocation did not close the downstream session")
			}
			// Do not defer this close until test cleanup: the connection-close
			// frame must reach Envoy after its upstream CONNECT was destroyed.
			_ = tr.Close()
			client := g.client(true)
			response := g.request(t, client, "/", "localhost")
			_ = response.Body.Close()
			client.CloseIdleConnections()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("proxy unhealthy after backend close %d: %s", iteration, response.Status)
			}
		}
	}) {
		return
	}
	// Concurrent parent sessions force QUIC congestion buffering of child
	// prefaces and parent close capsules. These writes bypass the HTTP encoder;
	// cleanup must report no Envoy buffer-accounting or QUICHE invariant errors.
	if !t.Run("concurrent-parents-prefaces-and-close-capsules", func(t *testing.T) {
		parents := make([]*wt.Session, 8)
		for i := range parents {
			_, parent, err := dial(ctx, g.tls.Clone(), "/wt")
			if err != nil {
				t.Fatal(err)
			}
			parents[i] = parent
		}
		finished := make(chan error, len(parents))
		for index, parent := range parents {
			go func(index int, parent *wt.Session) {
				defer parent.CloseWithError(0, "concurrent parent completed")
				results := make(chan error, 8)
				for childIndex := 0; childIndex < 8; childIndex++ {
					go func(childIndex int) {
						child, err := parent.OpenStreamSync(ctx)
						if err != nil {
							results <- err
							return
						}
						defer child.CancelRead(0)
						_ = child.SetDeadline(time.Now().Add(20 * time.Second))
						want := bytes.Repeat([]byte{byte(index), byte(childIndex), 0, 255}, 32<<10)
						written := make(chan error, 1)
						go func() {
							_, writeErr := child.Write(want)
							if writeErr == nil {
								writeErr = child.Close()
							}
							written <- writeErr
						}()
						got, readErr := io.ReadAll(io.LimitReader(child, int64(len(want)+1)))
						if writeErr := <-written; readErr == nil {
							readErr = writeErr
						}
						if readErr == nil && !bytes.Equal(got, want) {
							readErr = fmt.Errorf("parent %d child %d corruption", index, childIndex)
						}
						results <- readErr
					}(childIndex)
				}
				var first error
				for childIndex := 0; childIndex < 8; childIndex++ {
					if err := <-results; first == nil {
						first = err
					}
				}
				finished <- first
			}(index, parent)
		}
		for range parents {
			if err := <-finished; err != nil {
				t.Error(err)
			}
		}
	}) {
		return
	}
	waitForActiveUpstreams(t, &active, 1, "original WebTransport session after concurrent parents closed")
	// Keep a real child stream quiet while authorization is revoked.
	stream, e := sess.OpenStreamSync(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = stream.Write([]byte("ready")); e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadFull(stream, make([]byte, 5)); e != nil {
		t.Fatal(e)
	}
	before := accepted.Load()
	g.policy.set("fixture.default", true)
	defer g.policy.set("fixture.default", false)
	select {
	case <-sess.Context().Done():
	case <-time.After(4 * time.Second):
		t.Fatal("revoked WebTransport stayed open")
	}
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = stream.Read(make([]byte, 1)); e == nil {
		t.Fatal("revoked child stream stayed open")
	}
	waitForActiveUpstreams(t, &active, 0, "WebTransport sessions")
	waitForActiveUpstreams(t, &children, 0, "WebTransport child streams")
	r, _, e := dial(ctx, g.tls.Clone(), "/wt")
	if e == nil || r == nil || r.StatusCode != 403 {
		t.Fatalf("new revoked session: response=%v err=%v", r, e)
	}
	if accepted.Load() != before {
		t.Fatal("denied CONNECT reached backend")
	}
	g.policy.set("fixture.default", false)
	g.policy.outage(true)
	defer g.policy.outage(false)
	r, _, e = dial(ctx, g.tls.Clone(), "/wt")
	if e == nil || r == nil || r.StatusCode != 503 {
		t.Fatalf("authorization outage: response=%v err=%v", r, e)
	}
	tc := g.tls.Clone()
	tc.Certificates = nil
	r, _, e = dial(ctx, tc, "/wt")
	if e == nil {
		t.Fatalf("missing mTLS reached %v", r)
	}
}
