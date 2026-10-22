package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gorilla/websocket"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type policyServer struct {
	auth.UnimplementedAuthorizationServer
	mu                 sync.Mutex
	denied             map[string]bool
	checks             map[string]int
	unavailable        bool
	lastSession        string
	lastRecheck        bool
	subjectFingerprint [32]byte
}

func (p *policyServer) set(host string, denied bool) {
	p.mu.Lock()
	p.denied[host] = denied
	p.mu.Unlock()
}
func (p *policyServer) outage(value bool) { p.mu.Lock(); p.unavailable = value; p.mu.Unlock() }
func (p *policyServer) verdict(host, cert string, recheck bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if recheck {
		p.checks[host]++
	}
	if p.unavailable {
		return 503
	}
	decoded, err := url.QueryUnescape(cert)
	if err != nil {
		return 403
	}
	block, _ := pem.Decode([]byte(decoded))
	if block == nil {
		return 403
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !time.Now().Before(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) {
		return 403
	}
	if sha256.Sum256(leaf.Raw) != p.subjectFingerprint {
		return 403
	}
	if p.denied[host] {
		return 403
	}
	return 200
}
func (p *policyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/verify" {
		http.NotFound(w, r)
		return
	}
	p.mu.Lock()
	p.lastSession = r.Header.Get("X-OpenZTA-Session-ID")
	p.lastRecheck = r.Header.Get("X-OpenZTA-Reauthorization") == "true"
	p.mu.Unlock()
	xfcc := r.Header.Get("X-Forwarded-Client-Cert")
	cert := strings.TrimSuffix(strings.TrimPrefix(xfcc, `Cert="`), `"`)
	code := p.verdict(r.Header.Get("X-Original-Host"), cert, r.Header.Get("X-OpenZTA-Reauthorization") == "true")
	w.WriteHeader(code)
	if code != 200 {
		_, _ = io.WriteString(w, "policy denied")
	}
}
func (p *policyServer) Check(ctx context.Context, r *auth.CheckRequest) (*auth.CheckResponse, error) {
	resource := "tcp"
	if r.GetAttributes().GetRequest().GetHttp() != nil {
		resource = r.GetAttributes().GetContextExtensions()["openzta.resource_host"]
		if resource == "" || resource != r.GetAttributes().GetRequest().GetHttp().GetHost() || resource != r.GetAttributes().GetRequest().GetHttp().GetHeaders()["x-original-host"] {
			return nil, grpc.Errorf(codes.PermissionDenied, "missing or inconsistent resource binding")
		}
	}
	code := p.verdict(resource, r.GetAttributes().GetSource().GetCertificate(), r.GetAttributes().GetContextExtensions()["openzta.phase"] == "recheck")
	if code == 503 {
		return nil, grpc.Errorf(codes.Unavailable, "policy service unavailable")
	}
	grpcCode := codes.OK
	if code != 200 {
		grpcCode = codes.PermissionDenied
	}
	return &auth.CheckResponse{Status: &status.Status{Code: int32(grpcCode)}}, nil
}

type echoService interface{}

func grpcEchoServer(active *atomic.Int64) *grpc.Server {
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{ServiceName: "openzta.test.Echo", HandlerType: (*echoService)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Unary", Handler: func(s any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			in := new(wrapperspb.StringValue)
			if err := dec(in); err != nil {
				return nil, err
			}
			return in, nil
		}}}, Streams: []grpc.StreamDesc{{StreamName: "Chat", ClientStreams: true, ServerStreams: true, Handler: func(s any, stream grpc.ServerStream) error {
			active.Add(1)
			defer active.Add(-1)
			for {
				in := new(wrapperspb.StringValue)
				err := stream.RecvMsg(in)
				if err == io.EOF {
					return nil
				}
				if err != nil {
					return err
				}
				if err = stream.SendMsg(in); err != nil {
					return err
				}
			}
		}}}}, struct{}{})
	return server
}

type gateway struct {
	quicAddr     string
	pkiDir       string
	policy       *policyServer
	tls          *tls.Config
	addr         string
	tcpAddr      string
	name         string
	accepted     atomic.Int64
	activeTCP    atomic.Int64
	activeWS     atomic.Int64
	activeSSE    atomic.Int64
	activeGRPC   atomic.Int64
	activeUpload atomic.Int64
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}
func serve(t *testing.T, h http.Handler) int {
	t.Helper()
	ln := listen(t)
	server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(ln)
	t.Cleanup(func() { _ = server.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func testPKI(t *testing.T, dir string) (*tls.Config, string, string, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "acceptance CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caFile := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, client bool) (tls.Certificate, string, string) {
		// Production proxy service certificates may use P-384, including when
		// the authorization endpoint only negotiates TLS 1.2.
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		if client {
			usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
		if serial == 4 {
			leaf.NotBefore = time.Now().Add(-2 * time.Hour)
			leaf.NotAfter = time.Now().Add(-time.Hour)
		}
		if serial == 5 {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		if serial == 6 {
			leaf.NotBefore = time.Now().Add(time.Hour)
			leaf.NotAfter = time.Now().Add(2 * time.Hour)
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kp := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		cf := filepath.Join(dir, fmt.Sprintf("cert-%d.pem", serial))
		kf := filepath.Join(dir, fmt.Sprintf("key-%d.pem", serial))
		if err = os.WriteFile(cf, cp, 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(kf, kp, 0600); err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(cp, kp)
		if err != nil {
			t.Fatal(err)
		}
		return pair, cf, kf
	}
	_, serverCert, serverKey := issue(2, false)
	client, _, _ := issue(3, true)
	for _, serial := range []int64{4, 5, 6} {
		issue(serial, true)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: time.Now().Add(-time.Minute)}}}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "revoked.crl"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}), 0644); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	return &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{client}, MinVersion: tls.VersionTLS12, ServerName: "localhost"}, caFile, serverCert, serverKey
}

func newGateway(t *testing.T, configure ...func(map[string]any)) *gateway {
	t.Helper()
	image := os.Getenv("OPENZTA_ENVOY_IMAGE")
	if image == "" {
		t.Skip("set OPENZTA_ENVOY_IMAGE to the built OpenZTA native Envoy image")
	}
	dir := t.TempDir()
	// The container runs as uid 10001; these are throwaway acceptance keys.
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	tlsConfig, ca, cert, key := testPKI(t, dir)
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	p := &policyServer{denied: map[string]bool{}, checks: map[string]int{}, subjectFingerprint: sha256.Sum256(tlsConfig.Certificates[0].Certificate[0])}
	g := &gateway{pkiDir: dir, policy: p, tls: tlsConfig, name: fmt.Sprintf("openzta-acceptance-%d", time.Now().UnixNano())}
	authPort := serve(t, p)
	grpcAuthLn := listen(t)
	serviceCertificate, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	serviceFingerprint := sha256.Sum256(serviceCertificate.Certificate[0])
	grpcAuth := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serviceCertificate},
		ClientCAs:    tlsConfig.RootCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != serviceFingerprint {
				return fmt.Errorf("unexpected proxy service certificate")
			}
			return nil
		},
	})))
	auth.RegisterAuthorizationServer(grpcAuth, p)
	go grpcAuth.Serve(grpcAuthLn)
	t.Cleanup(grpcAuth.Stop)
	grpcLn := listen(t)
	gs := grpcEchoServer(&g.activeGRPC)
	go gs.Serve(grpcLn)
	t.Cleanup(gs.Stop)
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, e := upgrader.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		g.activeWS.Add(1)
		defer g.activeWS.Add(-1)
		defer c.Close()
		for {
			typ, msg, e := c.ReadMessage()
			if e != nil {
				return
			}
			if c.WriteMessage(typ, msg) != nil {
				return
			}
		}
	})
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		g.activeSSE.Add(1)
		defer g.activeSSE.Add(-1)
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if _, err := io.WriteString(w, "data: heartbeat\n\n"); err != nil {
					return
				}
				f.Flush()
			}
		}
	})
	mux.HandleFunc("/silent-sse", func(w http.ResponseWriter, r *http.Request) {
		g.activeSSE.Add(1)
		defer g.activeSSE.Add(-1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: initial\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		g.activeUpload.Add(1)
		defer g.activeUpload.Add(-1)
		h := sha256.New()
		_, err := io.Copy(h, r.Body)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "%x", h.Sum(nil))
	})
	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 256; i++ {
			if _, err := w.Write(bytes.Repeat([]byte{byte(i)}, 32768)); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/authority", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Host) })
	mux.HandleFunc("/operation", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Method, r.URL.RequestURI())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	httpPort := serve(t, mux)
	tcpLn := listen(t)
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			g.accepted.Add(1)
			g.activeTCP.Add(1)
			go func() {
				defer g.activeTCP.Add(-1)
				defer conn.Close()
				_, _ = io.WriteString(conn, "READY\n")
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	config := gatewayConfig(authPort, grpcAuthLn.Addr().(*net.TCPAddr).Port, httpPort, grpcLn.Addr().(*net.TCPAddr).Port, tcpLn.Addr().(*net.TCPAddr).Port, filepath.Base(ca), filepath.Base(cert), filepath.Base(key))
	config["layered_runtime"] = map[string]any{"layers": []any{map[string]any{"name": "openzta_protocol_defaults", "static_layer": map[string]any{"envoy.reloadable_features.enable_universal_header_validator": true}}}}
	for _, apply := range configure {
		apply(config)
	}
	file := filepath.Join(dir, "envoy.json")
	encoded, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(file, encoded, 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-d", "--name", g.name, "--add-host", "host.docker.internal:host-gateway", "-v", dir + ":/test:ro", "-p", "127.0.0.1::8443", "-p", "127.0.0.1::8444"}
	for _, value := range config["static_resources"].(map[string]any)["listeners"].([]any) {
		if _, ok := value.(map[string]any)["udp_listener_config"]; ok {
			args = append(args, "-p", "127.0.0.1::8443/udp")
			break
		}
	}
	args = append(args, image, "-c", "/test/envoy.json", "--concurrency", "2", "--log-level", "warning")
	run := exec.Command("docker", args...)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("start Envoy: %v %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", g.name).CombinedOutput()
			t.Logf("Envoy logs:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", g.name).Run()
	})
	for i := 0; i < 50; i++ {
		out, err := exec.Command("docker", "port", g.name, "8443/tcp").Output()
		if err == nil {
			g.addr = strings.TrimSpace(string(out))
		}
		out, err = exec.Command("docker", "port", g.name, "8444/tcp").Output()
		if err == nil {
			g.tcpAddr = strings.TrimSpace(string(out))
		}
		if out, e := exec.Command("docker", "port", g.name, "8443/udp").Output(); e == nil {
			g.quicAddr = strings.TrimSpace(string(out))
		}
		if g.addr != "" {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", g.addr, g.tls)
			if err == nil {
				_ = c.Close()
				return g
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("native Envoy did not become ready")
	return nil
}

func (g *gateway) client(h2 bool) *http.Client {
	tr := &http.Transport{TLSClientConfig: g.tls.Clone(), ForceAttemptHTTP2: h2}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}
func (g *gateway) request(t *testing.T, c *http.Client, path, host string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://"+g.addr+path, nil)
	req.Host = host
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHTTP2SSELastsBeyondLegacyTimeoutAndRevokesOnlyOneStream(t *testing.T) {
	g := newGateway(t)
	c := g.client(true)
	defer c.CloseIdleConnections()
	allowed := g.request(t, c, "/sse", "allowed.example")
	defer allowed.Body.Close()
	revoked := g.request(t, c, "/sse", "revoked.example")
	defer revoked.Body.Close()
	if allowed.ProtoMajor != 2 || revoked.ProtoMajor != 2 {
		t.Fatalf("HTTP/2 was not negotiated: %s %s", allowed.Proto, revoked.Proto)
	}
	end := time.Now().Add(17 * time.Second)
	rd := bufio.NewReader(allowed.Body)
	for time.Now().Before(end) {
		if _, err := rd.ReadString('\n'); err != nil {
			t.Fatalf("SSE ended before 17 seconds: %v", err)
		}
	}
	g.policy.set("revoked.example", true)
	deadline := time.Now().Add(4 * time.Second)
	buf := make([]byte, 256)
	for {
		_, err := revoked.Body.Read(buf)
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked idle SSE stayed open")
		}
	}
	if _, err := rd.ReadString('\n'); err != nil {
		t.Fatalf("revoking one HTTP/2 stream killed an allowed stream: %v", err)
	}
	g.policy.mu.Lock()
	checks := g.policy.checks["allowed.example"]
	g.policy.mu.Unlock()
	if checks < 3 {
		t.Fatalf("periodic checks missing: %d", checks)
	}
	waitForActiveUpstreams(t, &g.activeSSE, 1, "SSE")
}

func TestWebSocketTransparentAndRevokedWithoutNewMessages(t *testing.T) {
	g := newGateway(t)
	dialer := websocket.Dialer{TLSClientConfig: g.tls.Clone()}
	c, resp, err := dialer.Dial("wss://"+g.addr+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if resp.StatusCode != 101 {
		t.Fatal(resp.Status)
	}
	msg := []byte{0, 1, 2, 255}
	if err = c.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		t.Fatal(err)
	}
	typ, got, err := c.ReadMessage()
	if err != nil || typ != websocket.BinaryMessage || !bytes.Equal(msg, got) {
		t.Fatalf("binary echo: %d %x %v", typ, got, err)
	}
	g.policy.set("fixture.default", true)
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, _, err = c.ReadMessage(); err == nil {
		t.Fatal("revoked WebSocket stayed open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("WebSocket closed only by client read timeout")
	}
	waitForActiveUpstreams(t, &g.activeWS, 0, "WebSocket")
}

func TestGRPCUnaryAndIdleBidirectionalStreamRevocation(t *testing.T) {
	g := newGateway(t)
	conn, err := grpc.NewClient(g.addr, grpc.WithAuthority("localhost"), grpc.WithTransportCredentials(credentials.NewTLS(g.tls.Clone())))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	out := new(wrapperspb.StringValue)
	if err = conn.Invoke(ctx, "/openzta.test.Echo/Unary", wrapperspb.String("unary"), out); err != nil {
		t.Fatal(err)
	}
	if out.Value != "unary" {
		t.Fatal(out)
	}
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/openzta.test.Echo/Chat")
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.SendMsg(wrapperspb.String("bidi")); err != nil {
		t.Fatal(err)
	}
	if err = stream.RecvMsg(out); err != nil || out.Value != "bidi" {
		t.Fatalf("gRPC bidi: %v %v", out, err)
	}
	g.policy.set("localhost", true)
	done := make(chan error, 1)
	go func() { done <- stream.RecvMsg(out) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked gRPC stayed open")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("idle gRPC was not revoked")
	}
	waitForActiveUpstreams(t, &g.activeGRPC, 0, "gRPC")
}

func TestTCPHalfClosePreservesTheFinalUpstreamResponse(t *testing.T) {
	g := newGateway(t)
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", g.tcpAddr, g.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	rd := bufio.NewReader(c)
	if banner, err := rd.ReadString('\n'); err != nil || banner != "READY\n" {
		t.Fatalf("server-first banner: %q %v", banner, err)
	}
	payload := bytes.Repeat([]byte{0, 255, 13, 10, 97}, 32768)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rd)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("final response lost after client half-close: got=%d want=%d error=%v", len(got), len(payload), err)
	}
	g.waitForTCPUpstreamsClosed(t)
}

func TestTCPServerFirstByteTransparencyAndPolicyRevocation(t *testing.T) {
	g := newGateway(t)
	for name, payload := range map[string][]byte{"ssh": []byte("SSH-2.0-OpenZTA-test\r\n"), "smtp": []byte("EHLO test\r\n"), "redis": []byte("*1\r\n$4\r\nPING\r\n"), "postgres": {0, 0, 0, 8, 4, 210, 22, 47}, "mysql": {1, 0, 0, 0, 14}, "rdp": {3, 0, 0, 11, 6, 224, 0, 0, 0, 0, 0}} {
		t.Run(name, func(t *testing.T) {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", g.tcpAddr, g.tls)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			rd := bufio.NewReader(c)
			banner, err := rd.ReadString('\n')
			if err != nil || banner != "READY\n" {
				t.Fatalf("server-first banner: %q %v", banner, err)
			}
			if _, err = c.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(rd, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("opaque protocol changed: %x %v", got, err)
			}
		})
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", g.tcpAddr, g.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rd := bufio.NewReader(c)
	_, _ = rd.ReadString('\n')
	g.policy.set("tcp", true)
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err = rd.ReadByte(); err == nil {
		t.Fatal("revoked idle TCP stayed open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("TCP closed only by client timeout")
	}
	g.waitForTCPUpstreamsClosed(t)
	before := g.accepted.Load()
	denied, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", g.tcpAddr, g.tls)
	if err == nil {
		defer denied.Close()
		_ = denied.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 1)
		if n, _ := denied.Read(b); n > 0 {
			t.Fatal("denied connection received upstream bytes")
		}
	}
	if g.accepted.Load() != before {
		t.Fatal("denied TCP authorization reached upstream")
	}
}

func TestAuthorizationOutageClosesIdleStreamsAndRejectsNewRequests(t *testing.T) {
	g := newGateway(t)
	dialer := websocket.Dialer{TLSClientConfig: g.tls.Clone()}
	c, _, err := dialer.Dial("wss://"+g.addr+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g.policy.outage(true)
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, _, err = c.ReadMessage(); err == nil {
		t.Fatal("authorization outage left WebSocket open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("outage did not close the stream")
	}
	client := g.client(true)
	defer client.CloseIdleConnections()
	r := g.request(t, client, "/", "new.example")
	defer r.Body.Close()
	if r.StatusCode < 400 {
		t.Fatalf("fail open: %s", r.Status)
	}
}

func TestLargeBodiesAndMissingCertificate(t *testing.T) {
	g := newGateway(t)
	for _, h2 := range []bool{false, true} {
		c := g.client(h2)
		defer c.CloseIdleConnections()
		data := bytes.Repeat([]byte("OpenZTA"), 600000)
		req, _ := http.NewRequest("POST", "https://"+g.addr+"/upload", bytes.NewReader(data))
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		want := fmt.Sprintf("%x", sha256.Sum256(data))
		if string(got) != want {
			t.Fatalf("upload corrupted over HTTP/2=%v: %s", h2, got)
		}
		r = g.request(t, c, "/large", g.addr)
		body, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil || len(body) != 8<<20 {
			t.Fatalf("large download: %d %v", len(body), err)
		}
	}
	noCert := g.tls.Clone()
	noCert.Certificates = nil
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: noCert}, Timeout: 3 * time.Second}
	defer c.CloseIdleConnections()
	r, err := c.Get("https://" + g.addr + "/")
	if err == nil {
		defer r.Body.Close()
		t.Fatalf("mTLS accepted a client without certificate: %s", r.Status)
	}
}

// Application fixtures use private plaintext sockets. The gRPC policy endpoint
// requires a distinct proxy service certificate and a TLS 1.2/P-384 handshake.
func gatewayConfig(authPort, grpcAuthPort, httpPort, grpcPort, tcpPort int, ca, cert, key string) map[string]any {
	address := func(host string, port int) map[string]any {
		return map[string]any{"socket_address": map[string]any{"address": host, "port_value": port}}
	}
	cluster := func(name string, port int, h2 bool) map[string]any {
		c := map[string]any{"name": name, "cluster_type": map[string]any{"name": "envoy.clusters.dns", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.clusters.dns.v3.DnsCluster", "dns_lookup_family": "V4_ONLY"}}, "connect_timeout": "2s", "load_assignment": map[string]any{"cluster_name": name, "endpoints": []any{map[string]any{"lb_endpoints": []any{map[string]any{"endpoint": map[string]any{"address": address("host.docker.internal", port)}}}}}}}
		if h2 {
			c["typed_extension_protocol_options"] = map[string]any{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions", "explicit_http_config": map[string]any{"http2_protocol_options": map[string]any{}}}}
		}
		return c
	}
	recheck := map[string]any{"interval": "1s", "jitter": "0s", "max_session_duration": "120s"}
	socket := map[string]any{"name": "envoy.transport_sockets.tls", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext", "require_client_certificate": true, "disable_stateless_session_resumption": true, "disable_stateful_session_resumption": true, "common_tls_context": map[string]any{"alpn_protocols": []string{"h2", "http/1.1"}, "tls_certificates": []any{map[string]any{"certificate_chain": map[string]any{"filename": "/test/" + cert}, "private_key": map[string]any{"filename": "/test/" + key}}}, "validation_context": map[string]any{"trusted_ca": map[string]any{"filename": "/test/" + ca}}}}}
	tlsParams := map[string]any{"tls_minimum_protocol_version": "TLSv1_2", "tls_maximum_protocol_version": "TLSv1_3", "ecdh_curves": []string{"X25519", "P-256", "P-384"}}
	socket["typed_config"].(map[string]any)["common_tls_context"].(map[string]any)["tls_params"] = tlsParams
	grpcAuthCluster := cluster("grpc_auth", grpcAuthPort, true)
	grpcAuthCluster["transport_socket"] = map[string]any{"name": "envoy.transport_sockets.tls", "typed_config": map[string]any{
		"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext", "sni": "localhost",
		"common_tls_context": map[string]any{
			"alpn_protocols": []string{"h2"}, "tls_params": tlsParams,
			"tls_certificates":   []any{map[string]any{"certificate_chain": map[string]any{"filename": "/test/" + cert}, "private_key": map[string]any{"filename": "/test/" + key}}},
			"validation_context": map[string]any{"trusted_ca": map[string]any{"filename": "/test/" + ca}, "match_typed_subject_alt_names": []any{map[string]any{"san_type": "DNS", "matcher": map[string]any{"exact": "localhost"}}}},
		},
	}}
	authz := map[string]any{"name": "openzta.filters.http.continuous_authz", "typed_config": map[string]any{"@type": "type.googleapis.com/openzta.extensions.filters.continuous_authz.v1.HttpContinuousAuthz", "recheck": recheck, "resource_host": "fixture.default", "authorization": map[string]any{"http_service": map[string]any{"server_uri": map[string]any{"uri": "http://policy", "cluster": "auth", "timeout": "0.5s"}, "path_prefix": "/verify"}}}}
	route := func(name string) map[string]any {
		return map[string]any{"cluster": name, "timeout": "0s", "idle_timeout": "0s", "host_rewrite_literal": "fixture.backend"}
	}
	binding := func(resource string) map[string]any {
		return map[string]any{"filter_metadata": map[string]any{"openzta.continuous_authz": map[string]any{"resource_host": resource}}}
	}
	resourceRoute := func(resource string) map[string]any {
		return map[string]any{"match": map[string]any{"prefix": "/", "headers": []any{map[string]any{"name": ":authority", "string_match": map[string]any{"exact": resource}}}}, "route": route("http"), "metadata": binding(resource)}
	}
	hcm := map[string]any{"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", "stat_prefix": "test", "codec_type": "AUTO", "stream_idle_timeout": "30s", "forward_client_cert_details": "SANITIZE_SET", "set_current_client_cert_details": map[string]any{"cert": true}, "upgrade_configs": []any{map[string]any{"upgrade_type": "websocket"}}, "route_config": map[string]any{"virtual_hosts": []any{map[string]any{"name": "test", "domains": []string{"*"}, "routes": []any{map[string]any{"match": map[string]any{"prefix": "/openzta.test.Echo/"}, "route": route("grpc"), "metadata": binding("localhost")}, resourceRoute("allowed.example"), resourceRoute("revoked.example"), map[string]any{"match": map[string]any{"prefix": "/"}, "route": route("http")}}}}}, "http_filters": []any{authz, map[string]any{"name": "envoy.filters.http.grpc_web", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.filters.http.grpc_web.v3.GrpcWeb"}}, map[string]any{"name": "envoy.filters.http.router", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}}}
	networkAuth := map[string]any{"name": "openzta.filters.network.continuous_authz", "typed_config": map[string]any{"@type": "type.googleapis.com/openzta.extensions.filters.continuous_authz.v1.NetworkContinuousAuthz", "recheck": recheck, "authorization": map[string]any{"stat_prefix": "tcp_auth", "grpc_service": map[string]any{"envoy_grpc": map[string]any{"cluster_name": "grpc_auth"}, "timeout": "0.5s"}}}}
	listener := func(name string, port int, filters []any) map[string]any {
		return map[string]any{"name": name, "address": address("0.0.0.0", port), "filter_chains": []any{map[string]any{"transport_socket": socket, "transport_socket_connect_timeout": "1s", "filters": filters}}}
	}
	return map[string]any{"static_resources": map[string]any{"listeners": []any{listener("http", 8443, []any{map[string]any{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}}), listener("tcp", 8444, []any{networkAuth, map[string]any{"name": "envoy.filters.network.tcp_proxy", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", "stat_prefix": "tcp", "cluster": "tcp", "idle_timeout": "0s"}}})}, "clusters": []any{cluster("auth", authPort, false), grpcAuthCluster, cluster("http", httpPort, false), cluster("grpc", grpcPort, true), cluster("tcp", tcpPort, false)}}}
}

func TestGRPCWebUsesRealProtobufFraming(t *testing.T) {
	g := newGateway(t)
	client := g.client(false)
	defer client.CloseIdleConnections()
	payload, err := proto.Marshal(wrapperspb.String("grpc-web binary"))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	for _, contentType := range []string{"application/grpc-web+proto", "application/grpc-web-text+proto"} {
		t.Run(contentType, func(t *testing.T) {
			body := frame
			text := strings.Contains(contentType, "-text")
			if text {
				body = []byte(base64.StdEncoding.EncodeToString(frame))
			}
			req, _ := http.NewRequest("POST", "https://"+g.addr+"/openzta.test.Echo/Unary", bytes.NewReader(body))
			req.Header.Set("Content-Type", contentType)
			req.Header.Set("Accept", contentType)
			req.Header.Set("X-Grpc-Web", "1")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if text {
				// Streaming grpc-web may pad individual flushed base64 chunks.
				if len(data)%4 != 0 {
					t.Fatal("incomplete grpc-web-text base64 quartet")
				}
				var decoded []byte
				for len(data) > 0 {
					chunk := make([]byte, 3)
					n, err := base64.StdEncoding.Decode(chunk, data[:4])
					if err != nil {
						t.Fatal(err)
					}
					decoded = append(decoded, chunk[:n]...)
					data = data[4:]
				}
				data = decoded
			}
			if resp.StatusCode != 200 || len(data) < 5 || data[0] != 0 {
				t.Fatalf("invalid grpc-web response: %s %x", resp.Status, data)
			}
			length := int(binary.BigEndian.Uint32(data[1:5]))
			if length > len(data)-5 {
				t.Fatal("truncated protobuf frame")
			}
			out := new(wrapperspb.StringValue)
			if err := proto.Unmarshal(data[5:5+length], out); err != nil || out.Value != "grpc-web binary" {
				t.Fatalf("grpc-web payload: %v %v", out, err)
			}
			trailers := data[5+length:]
			if len(trailers) < 5 || trailers[0] != 128 || !bytes.Contains(trailers[5:], []byte("grpc-status:0")) {
				t.Fatalf("missing grpc-web trailers: %q", trailers)
			}
		})
	}
}

func TestHostCannotSelectAnUnrelatedResourcePolicy(t *testing.T) {
	for _, grpcAuth := range []bool{false, true} {
		t.Run(fmt.Sprintf("grpc_auth=%t", grpcAuth), func(t *testing.T) {
			g := newGateway(t, func(config map[string]any) {
				if !grpcAuth {
					return
				}
				listeners := config["static_resources"].(map[string]any)["listeners"].([]any)
				chain := listeners[0].(map[string]any)["filter_chains"].([]any)[0].(map[string]any)
				hcm := chain["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
				authorization := hcm["http_filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)["authorization"].(map[string]any)
				delete(authorization, "http_service")
				authorization["grpc_service"] = map[string]any{"envoy_grpc": map[string]any{"cluster_name": "grpc_auth"}, "timeout": "0.5s"}
			})
			for _, h2 := range []bool{false, true} {
				t.Run(fmt.Sprintf("h2=%t", h2), func(t *testing.T) {
					client := g.client(h2)
					defer client.CloseIdleConnections()
					const forged = "unrelated-allowed.example"
					g.policy.set(forged, false)
					g.policy.set("fixture.default", true)
					denied := g.request(t, client, "/authority", forged)
					denied.Body.Close()
					if denied.StatusCode != 403 {
						t.Fatalf("Host selected another resource's allow policy: %s", denied.Status)
					}
					g.policy.set(forged, true)
					g.policy.set("fixture.default", false)
					allowed := g.request(t, client, "/authority", forged)
					body, err := io.ReadAll(allowed.Body)
					allowed.Body.Close()
					if err != nil || allowed.StatusCode != 200 || string(body) != "fixture.backend" {
						t.Fatalf("configured resource/upstream authority changed: %s %q %v", allowed.Status, body, err)
					}
					stream := g.request(t, client, "/sse", forged)
					defer stream.Body.Close()
					if stream.StatusCode != 200 {
						t.Fatalf("bound SSE: %s", stream.Status)
					}
					g.policy.set("fixture.default", true)
					finished := make(chan error, 1)
					go func() { _, err := io.Copy(io.Discard, stream.Body); finished <- err }()
					select {
					case <-finished:
					case <-time.After(4 * time.Second):
						t.Fatal("SSE did not revoke the configured resource after a forged Host")
					}
					waitForActiveUpstreams(t, &g.activeSSE, 0, "SSE")
					g.policy.mu.Lock()
					forgedChecks := g.policy.checks[forged]
					g.policy.mu.Unlock()
					if forgedChecks != 0 {
						t.Fatalf("caller-selected resource reached policy service %d times", forgedChecks)
					}
				})
			}
		})
	}
}

func TestHTTP1SSEAndForgedAuthorizationHeaders(t *testing.T) {
	g := newGateway(t)
	client := g.client(false)
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "https://"+g.addr+"/sse", nil)
	req.Header.Set("X-Forwarded-Client-Cert", "attacker-supplied-certificate")
	req.Header.Set("X-OpenZTA-Reauthorization", "true")
	req.Header.Set("X-OpenZTA-Session-ID", "attacker-supplied-session")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 1 {
		t.Fatalf("HTTP/1 SSE: %s %s", resp.Status, resp.Proto)
	}
	g.policy.mu.Lock()
	session, phase := g.policy.lastSession, g.policy.lastRecheck
	g.policy.mu.Unlock()
	if phase || session == "" || session == "attacker-supplied-session" {
		t.Fatalf("trusted metadata forged: %q %v", session, phase)
	}
	g.policy.set("fixture.default", true)
	deadline := time.Now().Add(4 * time.Second)
	data := make([]byte, 256)
	for {
		if _, err := resp.Body.Read(data); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP/1 SSE not revoked")
		}
	}
	waitForActiveUpstreams(t, &g.activeSSE, 0, "SSE")
}

func TestTCPAuthorizationOutageFailsClosed(t *testing.T) {
	g := newGateway(t)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", g.tcpAddr, g.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	g.policy.outage(true)
	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("TCP left open after authz outage")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("TCP closed only by read timeout")
	}
	g.waitForTCPUpstreamsClosed(t)
	before := g.accepted.Load()
	conn2, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", g.tcpAddr, g.tls)
	if err == nil {
		defer conn2.Close()
		conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
		var b [1]byte
		if n, _ := conn2.Read(b[:]); n != 0 {
			t.Fatal("outage forwarded upstream bytes")
		}
	}
	if g.accepted.Load() != before {
		t.Fatal("outage opened an unauthorized upstream")
	}
}

func TestMaximumSessionLifetimeClosesAllowedIdleTransports(t *testing.T) {
	g := newGateway(t, func(config map[string]any) {
		var change func(any)
		change = func(v any) {
			switch v := v.(type) {
			case map[string]any:
				for k, x := range v {
					if k == "max_session_duration" {
						v[k] = "2s"
					} else {
						change(x)
					}
				}
			case []any:
				for _, x := range v {
					change(x)
				}
			}
		}
		change(config)
	})
	ws, _, err := (&websocket.Dialer{TLSClientConfig: g.tls.Clone()}).Dial("wss://"+g.addr+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	tcp, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", g.tcpAddr, g.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	reader := bufio.NewReader(tcp)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	ws.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("WebSocket survived maximum lifetime")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("WebSocket closed only by read timeout")
	}
	tcp.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("TCP survived maximum lifetime")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("TCP closed only by read timeout")
	}
}

func TestApplicationMethodsUseFixedAuthorizationEndpoint(t *testing.T) {
	g := newGateway(t)
	for _, h2 := range []bool{false, true} {
		client := g.client(h2)
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"} {
			t.Run(fmt.Sprintf("%s/h2=%t", method, h2), func(t *testing.T) {
				req, err := http.NewRequest(method, "https://"+g.addr+"/operation?unchanged=yes", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil || response.StatusCode != 200 {
					t.Fatalf("operation failed: status=%d body=%q err=%v", response.StatusCode, body, err)
				}
				if method != "HEAD" && string(body) != method+" /operation?unchanged=yes" {
					t.Fatalf("application operation changed: %q", body)
				}
			})
		}
		client.CloseIdleConnections()
	}
}

func TestNewTLSConnectionsAlwaysValidateClientIdentity(t *testing.T) {
	g := newGateway(t)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		cfg := g.tls.Clone()
		cfg.MinVersion = version
		cfg.MaxVersion = version
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
		transport := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		for attempt := 0; attempt < 3; attempt++ {
			response, err := client.Get("https://" + g.addr + "/")
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 {
				t.Fatalf("TLS %#x connection %d: status=%d err=%v", version, attempt, response.StatusCode, err)
			}
			if response.TLS.DidResume {
				t.Fatal("client identity bypassed a fresh TLS handshake through session resumption")
			}
		}
		transport.CloseIdleConnections()
	}
}

func TestIncompleteTLSHandshakesAreClosed(t *testing.T) {
	g := newGateway(t)
	for _, address := range []string{g.addr, g.tcpAddr} {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(4 * time.Second))
		var data [1]byte
		_, err = connection.Read(data[:])
		_ = connection.Close()
		if err == nil {
			t.Fatal("unexpected application data before TLS authorization")
		}
		if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
			t.Fatalf("TLS handshake remained open at %s", address)
		}
	}
	if g.accepted.Load() != 0 {
		t.Fatal("incomplete TLS handshake opened an upstream connection")
	}
}

func (g *gateway) waitForTCPUpstreamsClosed(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for g.activeTCP.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("revoked upstream connections remain active: %d", g.activeTCP.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForActiveUpstreams(t *testing.T, active *atomic.Int64, want int64, protocol string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for active.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s upstream count after revocation: got=%d want=%d", protocol, active.Load(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRevocationCancelsAnUnfinishedUploadAndItsUpstream(t *testing.T) {
	g := newGateway(t)
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%t", h2), func(t *testing.T) {
			g.policy.set("fixture.default", false)
			client := g.client(h2)
			defer client.CloseIdleConnections()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			request, err := http.NewRequest(http.MethodPost, "https://"+g.addr+"/upload", reader)
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				response *http.Response
				err      error
			}
			done := make(chan result, 1)
			go func() {
				response, err := client.Do(request)
				done <- result{response, err}
			}()
			go func() { _, _ = writer.Write(bytes.Repeat([]byte("x"), 16384)) }()
			// Leave the request body open and idle after its first chunk. Neither
			// an application response nor a client EOF can drive this revocation.
			waitForActiveUpstreams(t, &g.activeUpload, 1, "upload start")
			g.policy.set("fixture.default", true)
			select {
			case result := <-done:
				if result.response != nil {
					result.response.Body.Close()
					if result.response.StatusCode < 400 {
						t.Fatalf("revoked upload succeeded: %s", result.response.Status)
					}
				} else if result.err == nil {
					t.Fatal("revoked upload has no response or error")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("unfinished upload survived policy revocation")
			}
			waitForActiveUpstreams(t, &g.activeUpload, 0, "revoked upload")
		})
	}
}

func TestAllowedIdleSessionsSurviveTheHCMDefaultAndStillRevoke(t *testing.T) {
	g := newGateway(t, func(config map[string]any) {
		var change func(any)
		change = func(value any) {
			switch value := value.(type) {
			case map[string]any:
				for key, item := range value {
					if key == "stream_idle_timeout" {
						value[key] = "1s"
					} else {
						change(item)
					}
				}
			case []any:
				for _, item := range value {
					change(item)
				}
			}
		}
		change(config)
	})
	client := g.client(true)
	defer client.CloseIdleConnections()
	sse := g.request(t, client, "/silent-sse", g.addr)
	defer sse.Body.Close()
	initial := make([]byte, len("data: initial\n\n"))
	if _, err := io.ReadFull(sse.Body, initial); err != nil {
		t.Fatal(err)
	}
	sseDone := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, sse.Body); sseDone <- err }()
	ws, _, err := (&websocket.Dialer{TLSClientConfig: g.tls.Clone()}).Dial("wss://"+g.addr+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	grpcConnection, err := grpc.NewClient(g.addr, grpc.WithAuthority("localhost"), grpc.WithTransportCredentials(credentials.NewTLS(g.tls.Clone())))
	if err != nil {
		t.Fatal(err)
	}
	defer grpcConnection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := grpcConnection.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/openzta.test.Echo/Chat")
	if err != nil {
		t.Fatal(err)
	}
	message := wrapperspb.String("before idle")
	if err := stream.SendMsg(message); err != nil {
		t.Fatal(err)
	}
	if err := stream.RecvMsg(message); err != nil {
		t.Fatal(err)
	}
	tcp, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", g.tcpAddr, g.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tcpReader := bufio.NewReader(tcp)
	if _, err := tcpReader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// No application heartbeat on any transport. Route idle_timeout=0 must
	// override HCM's shorter default while periodic authorization remains live.
	select {
	case err := <-sseDone:
		t.Fatalf("allowed silent SSE ended at the HCM idle timeout: %v", err)
	case <-time.After(3 * time.Second):
	}
	for name, active := range map[string]*atomic.Int64{"SSE": &g.activeSSE, "WebSocket": &g.activeWS, "gRPC": &g.activeGRPC, "TCP": &g.activeTCP} {
		if active.Load() != 1 {
			t.Fatalf("allowed idle %s session was lost", name)
		}
	}
	if err := ws.WriteMessage(websocket.TextMessage, []byte("after idle")); err != nil {
		t.Fatal(err)
	}
	ws.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, data, err := ws.ReadMessage(); err != nil || string(data) != "after idle" {
		t.Fatalf("WebSocket after idle: %q %v", data, err)
	}
	if err := stream.SendMsg(wrapperspb.String("after idle")); err != nil {
		t.Fatal(err)
	}
	if err := stream.RecvMsg(message); err != nil || message.Value != "after idle" {
		t.Fatalf("gRPC after idle: %v %v", message, err)
	}
	for _, resource := range []string{"fixture.default", "localhost", "tcp"} {
		g.policy.set(resource, true)
	}
	select {
	case <-sseDone:
	case <-time.After(4 * time.Second):
		t.Fatal("silent SSE survived revocation")
	}
	ws.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("idle WebSocket survived revocation")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("WebSocket closed only by client timeout")
	}
	grpcDone := make(chan error, 1)
	go func() { grpcDone <- stream.RecvMsg(message) }()
	select {
	case err := <-grpcDone:
		if err == nil {
			t.Fatal("idle gRPC survived revocation")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("idle gRPC survived revocation")
	}
	tcp.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := tcpReader.ReadByte(); err == nil {
		t.Fatal("idle TCP survived revocation")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("TCP closed only by client timeout")
	}
	for name, active := range map[string]*atomic.Int64{"SSE": &g.activeSSE, "WebSocket": &g.activeWS, "gRPC": &g.activeGRPC, "TCP": &g.activeTCP} {
		waitForActiveUpstreams(t, active, 0, name)
	}
}
