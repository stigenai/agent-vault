package relay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRelayAbsoluteFormStreamsBodiesAndPassesLimits(t *testing.T) {
	const bodySize = 2 << 20
	central := newCentralHTTPProxy(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/limited" && req.ContentLength > 32 {
			http.Error(w, "central body limit", http.StatusRequestEntityTooLarge)
			return
		}
		bodyBytes, err := io.Copy(io.Discard, req.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		w.Header().Set("X-Body-Length", fmt.Sprint(bodyBytes))
		w.WriteHeader(http.StatusOK)
	})
	relayAddr, _ := startRelay(t, central.Addr().String(), nil)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: relayAddr})}}
	req, err := http.NewRequest(http.MethodPost, "http://service.example/upload", strings.NewReader("streamed"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Body-Length") != "8" {
		t.Fatalf("small request = status %d length %q", resp.StatusCode, resp.Header.Get("X-Body-Length"))
	}

	req, err = http.NewRequest(http.MethodPost, "http://service.example/upload", io.LimitReader(zeroReader{}, bodySize))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = bodySize
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Body-Length") != fmt.Sprint(bodySize) {
		t.Fatalf("large streamed request = status %d length %q", resp.StatusCode, resp.Header.Get("X-Body-Length"))
	}

	req, err = http.NewRequest(http.MethodPost, "http://service.example/limited", strings.NewReader(strings.Repeat("x", 64)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("central body limit status = %d, want 413", resp.StatusCode)
	}
}

func TestRelayCONNECTPreservesHalfClose(t *testing.T) {
	central := newCentralHTTPProxy(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect {
			t.Errorf("method = %q", req.Method)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("central writer cannot hijack")
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		payload, _ := io.ReadAll(rw)
		_, _ = conn.Write(append([]byte("received:"), payload...))
	})
	relayAddr, _ := startRelay(t, central.Addr().String(), nil)

	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	tcp := conn.(*net.TCPConn)
	_, _ = io.WriteString(tcp, "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n\r\npayload")
	if err := tcp.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(tcp)
	_ = tcp.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response, []byte("200 Connection Established")) || !bytes.HasSuffix(response, []byte("received:payload")) {
		t.Fatalf("half-close response = %q", response)
	}
}

func TestRelayPreservesWebSocketUpgrade(t *testing.T) {
	central := newCentralHTTPProxy(t, func(w http.ResponseWriter, req *http.Request) {
		if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			t.Errorf("Upgrade = %q", req.Header.Get("Upgrade"))
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		payload := make([]byte, 4)
		_, _ = io.ReadFull(rw, payload)
		_, _ = conn.Write(payload)
	})
	relayAddr, _ := startRelay(t, central.Addr().String(), nil)

	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET http://socket.example/chat HTTP/1.1\r\nHost: socket.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	_, _ = conn.Write([]byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping" {
		t.Fatalf("websocket echo = %q", echo)
	}
}

func TestRelayRejectsUnsafeListenerAndInvalidRequestLines(t *testing.T) {
	r, err := New(Options{RemoteAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	unsafe := &stubListener{addr: &net.TCPAddr{IP: net.IPv4zero, Port: 14322}}
	if err := r.Serve(unsafe); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("unsafe listener error = %v", err)
	}

	var dialed bool
	relayAddr, _ := startRelay(t, "unused:1", func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	})
	for _, tc := range []struct {
		name string
		line string
		code int
	}{
		{name: "origin form", line: "GET /secret HTTP/1.1\r\n\r\n", code: 400},
		{name: "https absolute form", line: "GET https://service.example/ HTTP/1.1\r\n\r\n", code: 400},
		{name: "invalid connect", line: "CONNECT service.example HTTP/1.1\r\n\r\n", code: 400},
		{name: "oversized", line: "GET http://service.example/" + strings.Repeat("x", DefaultRequestLineLimit) + " HTTP/1.1\r\n", code: 414},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", relayAddr)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(conn, tc.line)
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
			_ = conn.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.code {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.code)
			}
			_ = resp.Body.Close()
		})
	}
	if dialed {
		t.Fatal("invalid local requests reached the central dialer")
	}
}

func TestRelayNetworkListenerRequiresExplicitOptIn(t *testing.T) {
	networkAddr := &net.TCPAddr{IP: net.IPv4zero, Port: 14322}
	if err := requireAllowedListener(networkAddr, false); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("network listener without opt-in error = %v", err)
	}
	if err := requireAllowedListener(networkAddr, true); err != nil {
		t.Fatalf("explicit network listener rejected: %v", err)
	}
	loopbackAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 14322}
	if err := requireAllowedListener(loopbackAddr, true); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("network mode loopback error = %v", err)
	}
}

func TestRelayGracefulShutdownDrainsActiveStream(t *testing.T) {
	remoteClient, remoteServer := net.Pipe()
	dialed := make(chan struct{})
	relayAddr, relay := startRelay(t, "central:443", func(context.Context, string, string) (net.Conn, error) {
		close(dialed)
		return remoteClient, nil
	})
	local, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(local, "CONNECT service.example:443 HTTP/1.1\r\n\r\n")
	<-dialed

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done <- relay.Shutdown(ctx)
	}()
	select {
	case err := <-done:
		t.Fatalf("shutdown returned before stream drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	_ = local.Close()
	_ = remoteServer.Close()
	if err := <-done; err != nil {
		t.Fatalf("graceful shutdown: %v", err)
	}
}

func TestRelayForcedShutdownCancelsActiveStream(t *testing.T) {
	remoteClient, remoteServer := net.Pipe()
	defer remoteServer.Close()
	dialed := make(chan struct{})
	var once sync.Once
	relayAddr, relay := startRelay(t, "central:443", func(context.Context, string, string) (net.Conn, error) {
		once.Do(func() { close(dialed) })
		return remoteClient, nil
	})

	local, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(local, "CONNECT service.example:443 HTTP/1.1\r\n\r\n")
	<-dialed

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := relay.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forced shutdown error = %v, want deadline exceeded", err)
	}
	_ = local.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := local.Read(make([]byte, 1)); err == nil {
		t.Fatal("forced shutdown left local connection open")
	}
}

func TestRelayForcedShutdownCancelsPendingDial(t *testing.T) {
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	relayAddr, relay := startRelay(t, "central:443", func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		close(dialCanceled)
		return nil, ctx.Err()
	})
	local, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_, _ = io.WriteString(local, "CONNECT service.example:443 HTTP/1.1\r\n\r\n")
	<-dialStarted

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := relay.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forced shutdown error = %v, want deadline exceeded", err)
	}
	select {
	case <-dialCanceled:
	case <-time.After(time.Second):
		t.Fatal("pending central dial was not canceled")
	}
}

func startRelay(t *testing.T, remote string, dial DialContextFunc) (string, *Relay) {
	t.Helper()
	r, err := New(Options{RemoteAddr: remote, DialContext: dial})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = r.Shutdown(ctx)
		<-done
	})
	return listener.Addr().String(), r
}

func newCentralHTTPProxy(t *testing.T, handler http.HandlerFunc) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return listener
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type stubListener struct {
	addr net.Addr
}

func (s *stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (s *stubListener) Close() error              { return nil }
func (s *stubListener) Addr() net.Addr            { return s.addr }
