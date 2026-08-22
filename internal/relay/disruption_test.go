package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestRelayRecoversAfterSPIREAndBrokerDisruptions(t *testing.T) {
	domain := spiffeid.RequireTrustDomainFromString("cluster.example")
	ca := newRelayCA(t, "cluster.example")
	bundle := x509bundle.FromX509Authorities(domain, []*x509.Certificate{ca.cert})
	clientSVID := ca.issueSVID(t, "spiffe://cluster.example/ns/agents/sa/worker")
	clientMaterial := &relayMaterial{svid: clientSVID, bundle: bundle}
	serverMaterial := &relayMaterial{svid: ca.issueSVID(t, "spiffe://cluster.example/ns/vault/sa/proxy"), bundle: bundle}
	serverTLS := tlsconfig.MTLSServerConfig(serverMaterial, serverMaterial, workloadidentity.AuthorizeAgents(
		relayAgentLookup{id: clientSVID.ID.String(), agentID: "agent-worker"}, domain,
	))
	clientTLS := tlsconfig.MTLSClientConfig(clientMaterial, clientMaterial, workloadidentity.AuthorizeTrustDomains(domain))
	dial, err := newMTLSDialContext(clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	remoteAddr := listener.Addr().String()
	server := serveDisruptionBroker(t, listener, serverTLS, "one")
	relayAddr, _ := startRelay(t, remoteAddr, dial)
	client := disruptionClient(relayAddr)
	assertDisruptionStatus(t, client, http.StatusOK, "one")

	clientMaterial.setError(errors.New("SPIRE unavailable"))
	assertDisruptionStatus(t, client, http.StatusBadGateway, "")
	clientMaterial.setError(nil)
	assertDisruptionStatus(t, client, http.StatusOK, "one")

	shutdownHTTPServer(t, server)
	assertDisruptionStatus(t, client, http.StatusBadGateway, "")
	restarted, err := net.Listen("tcp", remoteAddr)
	if err != nil {
		t.Fatal(err)
	}
	server = serveDisruptionBroker(t, restarted, serverTLS, "two")
	defer shutdownHTTPServer(t, server)
	assertDisruptionStatus(t, client, http.StatusOK, "two")
}

func TestRelayProxyLoadDrainsConnections(t *testing.T) {
	central := newCentralHTTPProxy(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	relayAddr, relay := startRelay(t, central.Addr().String(), nil)
	client := disruptionClient(relayAddr)
	const requests = 64
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get("http://service.example/load")
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					err = fmt.Errorf("status %d", resp.StatusCode)
				}
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		relay.mu.Lock()
		active := len(relay.conns)
		relay.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay leaked %d connections after load", active)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRelayCentralConnectTimeoutIsBounded(t *testing.T) {
	r, err := New(Options{
		RemoteAddr:     "central:443",
		ConnectTimeout: 25 * time.Millisecond,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Serve(listener) }()
	start := time.Now()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "CONNECT service.example:443 HTTP/1.1\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway || time.Since(start) > 250*time.Millisecond {
		t.Fatalf("timeout response = %d after %s", resp.StatusCode, time.Since(start))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
}

func disruptionClient(relayAddr string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: relayAddr}),
		DisableKeepAlives: true,
	}}
}

func assertDisruptionStatus(t *testing.T, client *http.Client, want int, instance string) {
	t.Helper()
	resp, err := client.Get("http://service.example/disruption")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != want || (instance != "" && resp.Header.Get("X-Broker-Instance") != instance) {
		t.Fatalf("response = status %d instance %q, want %d/%q", resp.StatusCode, resp.Header.Get("X-Broker-Instance"), want, instance)
	}
}

func serveDisruptionBroker(t *testing.T, listener net.Listener, tlsConfig *tls.Config, instance string) *http.Server {
	t.Helper()
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id, err := x509svid.IDFromCert(req.TLS.PeerCertificates[0])
		if err != nil || id.String() != "spiffe://cluster.example/ns/agents/sa/worker" {
			http.Error(w, "wrong identity", http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Broker-Instance", instance)
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = server.Serve(tls.NewListener(listener, tlsConfig)) }()
	return server
}

func shutdownHTTPServer(t *testing.T, server *http.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
