package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

func udpEchoContainer(t *testing.T) string {
	t.Helper()
	image := os.Getenv("OPENZTA_ENVOY_IMAGE")
	if image == "" {
		t.Skip("set OPENZTA_ENVOY_IMAGE to the built OpenZTA native Envoy image")
	}
	arch, err := exec.Command("docker", "image", "inspect", "--format", "{{.Architecture}}", image).Output()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "udp-echo")
	build := exec.Command("go", "build", "-o", binary, "../fixtures/udp-echo/main.go")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+strings.TrimSpace(string(arch)))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build UDP fixture: %v %s", err, out)
	}
	name := fmt.Sprintf("openzta-udp-acceptance-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Logf("UDP fixture logs: %s", out)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	cmd := exec.Command("docker", "run", "-d", "--name", name, "--pull=never", "--network", "bridge", "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "64m", "--mount", "type=bind,source="+dir+",target=/fixture,readonly", "--entrypoint", "/fixture/udp-echo", image)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start UDP fixture: %v %s", err, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if strings.Contains(string(logs), "udp-ready") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP fixture did not become ready: %s", logs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	address, err := exec.Command("docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimSpace(string(address))
	if net.ParseIP(host) == nil {
		t.Fatalf("invalid UDP fixture address %q", host)
	}
	return host
}

func newUDPGateway(t *testing.T) (*gateway, string) {
	upstream := udpEchoContainer(t)
	path := "/.well-known/masque/udp/echo/9005/"
	g := newGateway(t, func(config map[string]any) {
		resources := config["static_resources"].(map[string]any)
		hcm := resources["listeners"].([]any)[0].(map[string]any)["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
		hcm["http2_protocol_options"] = map[string]any{"allow_connect": true}
		hcm["access_log"] = []any{map[string]any{"name": "envoy.access_loggers.stdout", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog", "log_format": map[string]any{"json_format": map[string]any{"status": "%RESPONSE_CODE%", "details": "%RESPONSE_CODE_DETAILS%", "flags": "%RESPONSE_FLAGS%", "upstream": "%UPSTREAM_HOST%", "cluster": "%UPSTREAM_CLUSTER%", "transport_failure": "%UPSTREAM_TRANSPORT_FAILURE_REASON%"}}}}}
		hcm["upgrade_configs"] = append(hcm["upgrade_configs"].([]any), map[string]any{"upgrade_type": "CONNECT"}, map[string]any{"upgrade_type": "connect-udp"})
		route := map[string]any{"cluster": "udp", "timeout": "0s", "idle_timeout": "0s", "upgrade_configs": []any{map[string]any{"upgrade_type": "CONNECT", "connect_config": map[string]any{}}, map[string]any{"upgrade_type": "connect-udp", "connect_config": map[string]any{}}}}
		host := hcm["route_config"].(map[string]any)["virtual_hosts"].([]any)[0].(map[string]any)
		host["routes"] = []any{
			map[string]any{"match": map[string]any{"connect_matcher": map[string]any{}, "headers": []any{map[string]any{"name": ":path", "string_match": map[string]any{"exact": path}}, map[string]any{"name": ":protocol", "string_match": map[string]any{"exact": "connect-udp"}}}}, "route": route},
			map[string]any{"match": map[string]any{"path": path, "headers": []any{map[string]any{"name": "upgrade", "string_match": map[string]any{"exact": "connect-udp"}}}}, "route": route},
			map[string]any{"match": map[string]any{"path": "/http-only"}, "route": map[string]any{"cluster": "http", "timeout": "0s"}},
			map[string]any{"match": map[string]any{"prefix": "/"}, "direct_response": map[string]any{"status": 403}},
		}
		resources["clusters"] = append(resources["clusters"].([]any), map[string]any{"name": "udp", "type": "STATIC", "connect_timeout": "2s", "upstream_config": map[string]any{"name": "envoy.filters.connection_pools.http.udp", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.upstreams.http.udp.v3.UdpConnectionPoolProto"}}, "load_assignment": map[string]any{"cluster_name": "udp", "endpoints": []any{map[string]any{"lb_endpoints": []any{map[string]any{"endpoint": map[string]any{"address": map[string]any{"socket_address": map[string]any{"address": upstream, "port_value": 9005, "protocol": "UDP"}}}}}}}}})
	}, withQUIC, func(config map[string]any) {
		for _, v := range config["static_resources"].(map[string]any)["listeners"].([]any) {
			listener := v.(map[string]any)
			if listener["name"] != "quic" {
				continue
			}
			hcm := listener["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
			hcm["http3_protocol_options"].(map[string]any)["allow_extended_connect"] = true
		}
	})
	return g, path
}

func TestConnectUDPPacketSemanticsAndRevocation(t *testing.T) {
	g, path := newUDPGateway(t)
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("HTTP%d", version), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			var reader *bufio.Reader
			var writer io.Writer
			var close func()
			if version == 1 {
				tc := g.tls.Clone()
				tc.NextProtos = []string{"http/1.1"}
				conn, err := tls.Dial("tcp", g.addr, tc)
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
				t.Cleanup(func() { _ = conn.Close() })
				_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n", path)
				if err != nil {
					t.Fatal(err)
				}
				reader = bufio.NewReader(conn)
				response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 101 || response.Header.Get("Capsule-Protocol") != "?1" {
					t.Fatalf("upgrade: %s %v", response.Status, response.Header)
				}
				writer = conn
				close = func() { _ = conn.Close() }
			} else {
				pr, pw := io.Pipe()
				defer pr.Close()
				defer pw.Close()
				request, _ := http.NewRequestWithContext(ctx, "CONNECT", "https://localhost"+path, pr)
				request.Header.Set("Capsule-Protocol", "?1")
				var client *http.Client
				if version == 3 {
					request.Proto = "connect-udp"
					client = g.quicClient(t, g.tls.Clone())
				} else {
					request.Header.Set(":protocol", "connect-udp")
					transport := &http2.Transport{TLSClientConfig: g.tls.Clone(), DialTLSContext: func(ctx context.Context, network, address string, tc *tls.Config) (net.Conn, error) {
						return (&tls.Dialer{Config: tc}).DialContext(ctx, network, g.addr)
					}}
					defer transport.CloseIdleConnections()
					client = &http.Client{Transport: transport}
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.ProtoMajor != version || response.StatusCode != 200 || response.Header.Get("Capsule-Protocol") != "?1" {
					t.Fatalf("handshake: %s %s %v", response.Proto, response.Status, response.Header)
				}
				reader = bufio.NewReader(response.Body)
				writer = pw
				close = func() { cancel(); _ = response.Body.Close(); _ = pw.Close() }
			}
			defer close()
			// Unknown types and context IDs must not turn into upstream packets.
			if _, err := writer.Write([]byte{0x21, 1, 99, 0, 2, 1, 88}); err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{0, 4, 1200, 4096, 65507} {
				payload := bytes.Repeat([]byte{0xa5}, size)
				frame := quicvarint.Append([]byte{0}, uint64(size+1))
				frame = append(frame, 0)
				frame = append(frame, payload...)
				if _, err := writer.Write(frame); err != nil {
					t.Fatal(err)
				}
				kind, err := quicvarint.Read(reader)
				if err != nil {
					t.Fatalf("packet size %d: %v", size, err)
				}
				length, err := quicvarint.Read(reader)
				if err != nil {
					t.Fatal(err)
				}
				if kind != 0 || length != uint64(size+1) {
					t.Fatalf("packet size %d changed: kind=%d length=%d", size, kind, length)
				}
				echo := make([]byte, int(length))
				if _, err = io.ReadFull(reader, echo); err != nil {
					t.Fatal(err)
				}
				if echo[0] != 0 || !bytes.Equal(echo[1:], payload) {
					t.Fatalf("packet size %d changed", size)
				}
			}
			var floodDone chan error
			if version == 3 {
				// Stop consuming the response while sending enough echo traffic to
				// fill the QUIC receive window. Reauthorization must still run and
				// release a writer blocked by response-side backpressure.
				floodDone = make(chan error, 1)
				go func() {
					frame := quicvarint.Append([]byte{0}, 65508)
					frame = append(frame, 0)
					frame = append(frame, make([]byte, 65507)...)
					for range 64 {
						if _, err := writer.Write(frame); err != nil {
							floodDone <- err
							return
						}
					}
					floodDone <- nil
				}()
				time.Sleep(200 * time.Millisecond)
			}
			g.policy.set("fixture.default", true)
			defer g.policy.set("fixture.default", false)
			done := make(chan error, 1)
			go func() {
				for {
					if _, err := reader.ReadByte(); err != nil {
						done <- err
						return
					}
				}
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("quiet UDP tunnel survived revocation")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("quiet UDP tunnel survived revocation")
			}
			if floodDone != nil {
				select {
				case <-floodDone:
				case <-time.After(2 * time.Second):
					t.Fatal("UDP writer stayed blocked after revocation")
				}
			}
		})
	}
}

func TestQUICDatagramFramesAuthorizationAndRevocation(t *testing.T) {
	g, path := newUDPGateway(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	tc := g.tls.Clone()
	tc.NextProtos = []string{http3.NextProtoH3}
	connection, err := quic.DialAddr(ctx, g.quicAddr, tc, &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 2 * time.Second, KeepAlivePeriod: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "")
	transport := &http3.Transport{EnableDatagrams: true, DisableCompression: true}
	defer transport.Close()
	client := transport.NewClientConn(connection)
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !client.Settings().EnableDatagrams || !client.Settings().EnableExtendedConnect {
		t.Fatal("HTTP/3 DATAGRAM and extended CONNECT were not negotiated")
	}
	// A header on an ordinary application request must not turn its response into
	// a capsule stream or expose an unreliable request-body injection path.
	plain, err := client.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/http-only", nil)
	ordinary.Header.Set("Capsule-Protocol", "?1")
	if err = plain.SendRequestHeader(ordinary); err != nil {
		t.Fatal(err)
	}
	_ = plain.Close()
	ordinaryResponse, err := plain.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(ordinaryResponse.Body)
	_ = ordinaryResponse.Body.Close()
	if err != nil || ordinaryResponse.StatusCode != 200 || string(data) != "ok" {
		t.Fatalf("ordinary HTTP capsule-header isolation: status=%d body=%q error=%v", ordinaryResponse.StatusCode, data, err)
	}
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(ctx, "CONNECT", "https://localhost"+path, nil)
	request.Proto = "connect-udp"
	request.Header.Set("Capsule-Protocol", "?1")
	if err = stream.SendRequestHeader(request); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Logf("CONNECT-UDP error headers: %v", response.Header)
		_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("CONNECT-UDP status=%d headers=%v body=%q", response.StatusCode, response.Header, data)
	}
	go func() { _, _ = io.Copy(io.Discard, response.Body) }()
	packet := []byte("\x00native-DATAGRAM\x00\xff")
	if err = stream.SendDatagram(packet); err != nil {
		t.Fatal(err)
	}
	echoed, err := stream.ReceiveDatagram(ctx)
	if err != nil || !bytes.Equal(packet, echoed) {
		t.Fatalf("native DATAGRAM frames did not roundtrip: %x %v", echoed, err)
	}
	g.policy.set("fixture.default", true)
	done := make(chan error, 1)
	go func() { _, err := stream.ReceiveDatagram(ctx); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked DATAGRAM tunnel remained open")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked DATAGRAM tunnel remained open")
	}
	denied, err := client.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = denied.SendRequestHeader(request); err != nil {
		t.Fatal(err)
	}
	rejection, err := denied.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer rejection.Body.Close()
	if rejection.StatusCode != 403 {
		t.Fatalf("new DATAGRAM tunnel after revocation: %d", rejection.StatusCode)
	}
}
