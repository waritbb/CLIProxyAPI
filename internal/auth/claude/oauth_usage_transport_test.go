package claude

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type usageListenerDialer struct{ address string }

func (d usageListenerDialer) Dial(network, _ string) (net.Conn, error) {
	return net.Dial(network, d.address)
}
func (d usageListenerDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func TestOAuthUsageCancellationClosesPendingTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	started := make(chan struct{})
	closed := make(chan error, 1)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			closed <- errAccept
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var first [1]byte
		if _, errRead := io.ReadFull(conn, first[:]); errRead != nil {
			closed <- errRead
			return
		}
		close(started)
		_, errRead := io.Copy(io.Discard, conn)
		closed <- errRead
	}()
	client := NewAnthropicHttpClient(nil)
	t.Cleanup(client.CloseIdleConnections)
	client.Transport.(*utlsRoundTripper).dialer = usageListenerDialer{address: listener.Addr().String()}
	oauth := &ClaudeAuth{httpClient: client}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan error, 1)
	go func() { _, errFetch := oauth.FetchOAuthUsage(ctx, "fixture-token"); returned <- errFetch }()
	select {
	case <-started:
	case errClosed := <-closed:
		t.Fatalf("listener failed before handshake: %v", errClosed)
	case <-time.After(3 * time.Second):
		t.Fatal("TLS handshake never began")
	}
	cancel()
	select {
	case errFetch := <-returned:
		if !errors.Is(errFetch, context.Canceled) {
			t.Fatalf("fetch error = %v", errFetch)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("usage request did not return after cancellation")
	}
	select {
	case errClosed := <-closed:
		if errClosed != nil {
			t.Fatalf("connection did not close cleanly: %v", errClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("pending TLS connection survived usage cancellation")
	}
}
