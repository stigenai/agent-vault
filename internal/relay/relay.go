// Package relay provides the local compatibility boundary between an
// untrusted workload and the Agent Vault proxy. It validates only the first
// proxy request line, then copies the connection byte-for-byte so request
// bodies, credentials, upgrades, and tunnels are never interpreted.
package relay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const DefaultRequestLineLimit = 8 * 1024

// DialContextFunc opens the relay's connection to the central proxy. A later
// transport layer can supply a SPIFFE-aware TLS dialer without changing the
// local proxy implementation.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type Options struct {
	RemoteAddr       string
	DialContext      DialContextFunc
	RequestLineLimit int
}

type Relay struct {
	remoteAddr string
	dial       DialContextFunc
	lineLimit  int

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	started  bool
	stopping bool
	wg       sync.WaitGroup
	dialCtx  context.Context
	cancel   context.CancelFunc
}

func New(opts Options) (*Relay, error) {
	if strings.TrimSpace(opts.RemoteAddr) == "" {
		return nil, errors.New("relay remote address is required")
	}
	dial := opts.DialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	lineLimit := opts.RequestLineLimit
	if lineLimit == 0 {
		lineLimit = DefaultRequestLineLimit
	}
	if lineLimit < 64 {
		return nil, errors.New("relay request-line limit must be at least 64 bytes")
	}
	dialCtx, cancel := context.WithCancel(context.Background())
	return &Relay{
		remoteAddr: opts.RemoteAddr,
		dial:       dial,
		lineLimit:  lineLimit,
		conns:      make(map[net.Conn]struct{}),
		dialCtx:    dialCtx,
		cancel:     cancel,
	}, nil
}

// Serve accepts local proxy connections. The listener must be bound to an
// explicit loopback address; wildcard and non-TCP listeners fail closed.
func (r *Relay) Serve(listener net.Listener) error {
	if err := requireLoopback(listener.Addr()); err != nil {
		_ = listener.Close()
		return err
	}

	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		_ = listener.Close()
		return errors.New("relay can only be served once")
	}
	if r.stopping {
		r.mu.Unlock()
		_ = listener.Close()
		return errors.New("relay is shutting down")
	}
	r.started = true
	r.listener = listener
	r.mu.Unlock()

	for {
		conn, err := listener.Accept()
		if err != nil {
			r.mu.Lock()
			stopping := r.stopping
			r.mu.Unlock()
			if stopping || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept relay connection: %w", err)
		}
		if !r.trackAccepted(conn) {
			_ = conn.Close()
			continue
		}
		go r.serveConn(conn)
	}
}

// Shutdown stops accepting new work and waits for active byte streams to
// drain. When ctx expires it cancels pending dials and closes every remaining
// connection.
func (r *Relay) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	r.stopping = true
	listener := r.listener
	r.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		r.cancel()
		r.closeConnections()
		<-done
		return ctx.Err()
	}
}

func (r *Relay) serveConn(local net.Conn) {
	defer r.wg.Done()
	defer r.untrack(local)
	defer local.Close()

	reader := bufio.NewReaderSize(local, r.lineLimit+1)
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > r.lineLimit {
		writeError(local, 414, "proxy request line too large")
		return
	}
	if err != nil {
		return
	}
	line = bytes.Clone(line)
	if !validProxyRequestLine(line) {
		writeError(local, 400, "CONNECT or absolute-form proxy request required")
		return
	}

	remote, err := r.dial(r.dialCtx, "tcp", r.remoteAddr)
	if err != nil {
		writeError(local, 502, "central proxy unavailable")
		return
	}
	if !r.track(remote) {
		_ = remote.Close()
		writeError(local, 503, "relay is shutting down")
		return
	}
	defer r.untrack(remote)
	defer remote.Close()

	clientToRemote := io.MultiReader(bytes.NewReader(line), reader)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, clientToRemote)
		closeWrite(remote)
		closeRead(local)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(local, remote)
		closeWrite(local)
		closeRead(remote)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func validProxyRequestLine(raw []byte) bool {
	line := strings.TrimSuffix(string(raw), "\n")
	line = strings.TrimSuffix(line, "\r")
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return false
	}
	if parts[2] != "HTTP/1.0" && parts[2] != "HTTP/1.1" {
		return false
	}
	if parts[0] == httpMethodConnect {
		host, port, err := net.SplitHostPort(parts[1])
		if err != nil || host == "" {
			return false
		}
		portNumber, err := strconv.Atoi(port)
		return err == nil && portNumber > 0 && portNumber <= 65535
	}
	parsed, err := url.ParseRequestURI(parts[1])
	return err == nil && parsed.IsAbs() && parsed.Host != "" && strings.EqualFold(parsed.Scheme, "http")
}

const httpMethodConnect = "CONNECT"

func requireLoopback(addr net.Addr) error {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		return fmt.Errorf("relay listener must use an explicit loopback TCP address, got %q", addr.String())
	}
	return nil
}

func (r *Relay) track(conn net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return false
	}
	r.conns[conn] = struct{}{}
	return true
}

// trackAccepted couples the connection registration with WaitGroup.Add while
// holding the same lock Shutdown uses to enter the stopping state. This keeps
// Add from racing a Wait that has already observed zero active handlers.
func (r *Relay) trackAccepted(conn net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return false
	}
	r.conns[conn] = struct{}{}
	r.wg.Add(1)
	return true
}

func (r *Relay) untrack(conn net.Conn) {
	r.mu.Lock()
	delete(r.conns, conn)
	r.mu.Unlock()
}

func (r *Relay) closeConnections() {
	r.mu.Lock()
	conns := make([]net.Conn, 0, len(r.conns))
	for conn := range r.conns {
		conns = append(conns, conn)
	}
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func closeWrite(conn net.Conn) {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
}

func closeRead(conn net.Conn) {
	if half, ok := conn.(interface{ CloseRead() error }); ok {
		_ = half.CloseRead()
	}
}

func writeError(conn net.Conn, status int, message string) {
	body := message + "\n"
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", status, statusText(status), len(body), body)
}

func statusText(status int) string {
	switch status {
	case 400:
		return "Bad Request"
	case 414:
		return "URI Too Long"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Error"
	}
}
