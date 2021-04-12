package selective_mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/pkg/errors"
)

const (
	DefaultUpstreamConnectTimeout = 10 * time.Second

	// that is the type for alert records during the TLS handshake, e.g. when the server is unable to complete the handshake
	// see https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html
	alertTLSHandshakeAlertRecordHeader = 0x15
)

var (
	ErrNoCertificate = errors.New("MitM: no certificates configured")

	okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

	errClosedListener = errors.New("closed listener")
)

type MITMProxy struct {
	// GetCertificate should return a tls.Certificate based on the given Request and ClientHelloInfo
	// If we don't have a certificate for the requested upstream, then this should return
	// (nil, ErrNoCertificate); in which case the connection will be tunneled encrypted, as a normal
	// HTTP proxy would do.
	GetCertificate func(*http.Request, *tls.ClientHelloInfo) (*tls.Certificate, error)

	// Wrap specifies a function for optionally wrapping upstream for
	// inspecting the decrypted HTTP request and response.
	// Can be left nil.
	Wrap func(upstream *httputil.ReverseProxy) http.Handler

	// TLSClientConfig specifies the tls.Config to use when establishing
	// an upstream connection for proxying.
	TLSClientConfig *tls.Config

	// Timeout to connect upstream.
	//
	// The timeout includes name resolution, if required.
	// When using TCP, and the host in the address parameter resolves to
	// multiple IP addresses, the timeout is spread over each consecutive
	// dial, such that each is given an appropriate fraction of the time
	// to connect.
	//
	// Defaults to DefaultUpstreamConnectTimeout
	UpstreamConnectTimeout time.Duration

	// Optional handler for any error that might happen while handling a CONNECT request
	// This is optional, and would typically be used for logging
	// If defined, it must be a thread-safe function
	// Shame there's no standard logging interface in go :(
	ConnectErrorLogger func(err error)
}

func (p *MITMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if err := p.handleConnect(w, r); err != nil && p.ConnectErrorLogger != nil {
			p.ConnectErrorLogger(err)
		}
	} else {
		// plain HTTP
		reverseProxy := &httputil.ReverseProxy{
			Director: func(r *http.Request) {
				r.URL.Host = r.Host
				r.URL.Scheme = "http"
			},
		}
		p.Wrap(reverseProxy).ServeHTTP(w, r)
	}
}

func (p *MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) error {
	// connect to the upstream server
	timeout := p.UpstreamConnectTimeout
	if timeout <= 0 {
		timeout = DefaultUpstreamConnectTimeout
	}
	upstreamConnection, err := net.DialTimeout("tcp", r.Host, timeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return errors.Wrap(err, "unable to connect to upstream server")
	}
	defer upstreamConnection.Close()

	// hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return errors.Wrap(err, "unable to connect to hijack request")
	}
	hijackedConnection, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return errors.Wrap(err, "unable to connect to hijack request")
	}
	defer hijackedConnection.Close()

	// at this point, we can move on to the next stage and tell the client to go ahead and start the tunnel
	if _, err := hijackedConnection.Write(okHeader); err != nil {
		return errors.Wrap(err, "unable to write OK header")
	}

	// next, try to MitM that connection
	wrappedConnection := &tlsHelloConnection{Conn: hijackedConnection}
	var clientHelloInfo *tls.ClientHelloInfo
	serverConnection := tls.Server(wrappedConnection, &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			clientHelloInfo = info
			return p.GetCertificate(r, info)
		},
	})
	defer serverConnection.Close()
	handshakeErr := serverConnection.Handshake()
	if handshakeErr != nil {
		if handshakeErr == ErrNoCertificate {
			// we don't have a certificate for the target, just establish a tunnel like a normal proxy
			return errors.Wrap(p.establishEncryptedTunnel(upstreamConnection, wrappedConnection),
				"unable to establish non-MitM tunnel")
		}

		// unexpected error, let the client know, and abort
		// no error checking, this is just best effort here
		_, err := wrappedConnection.flushWithheldWrittenBuffer()
		return errors.Wrap(err, "unable to complete TLS handshake")
	}

	// no error during the handshake, we're all set to MitM everything on this connection!
	wrappedConnection.resumeNormalOperation()
	return errors.Wrap(p.establishMitMTunnel(clientHelloInfo, upstreamConnection, serverConnection),
		"unable to establish MitM tunnel")
}

// establishEncryptedTunnel establishes a two-way, encrypted, non-MitM tunnel, just like a normal proxy would do
// it blocks until either connection is closed
func (p *MITMProxy) establishEncryptedTunnel(upstreamConnection net.Conn, tlsHelloConnection *tlsHelloConnection) error {
	// re-play the client's hello message to the upstream server
	if _, err := upstreamConnection.Write(tlsHelloConnection.read); err != nil {
		return err
	}

	// and then let both talk to each other directly
	waitChan := make(chan error, 2)
	pipe := func(source, destination net.Conn) {
		_, err := io.Copy(destination, source)
		waitChan <- err
	}

	go pipe(upstreamConnection, tlsHelloConnection.Conn)
	go pipe(tlsHelloConnection.Conn, upstreamConnection)

	return <-waitChan
}

// establishMitMTunnel establishes a MitM tunnel through which the proxy's `Wrap`per function
// can inspect or modify requests and responses.
func (p *MITMProxy) establishMitMTunnel(clientHelloInfo *tls.ClientHelloInfo, upstreamConnection, serverConnection net.Conn) error {
	var config *tls.Config
	if p.TLSClientConfig == nil {
		config = &tls.Config{}
	} else {
		config = p.TLSClientConfig.Clone()
	}
	config.ServerName = clientHelloInfo.ServerName
	clientConn := tls.Client(upstreamConnection, config)
	defer clientConn.Close()

	reverseProxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Host = r.Host
			r.URL.Scheme = "https"
		},
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return clientConn, nil
			},
		},
	}

	closedChan := make(chan interface{})
	err := http.Serve(&oneShotListener{c: &onCloseConn{
		Conn: serverConnection,
		f: func() {
			close(closedChan)
		},
	}}, p.Wrap(reverseProxy))

	<-closedChan
	if err == errClosedListener {
		return nil
	}
	return err
}

// a wrapper around `net.Conn`s to be able to try starting a MitM TLS session, and if that fails
// (e.g. because we don't have a certificate for that hostname), being able to let the client
// resume communicating seamlessly with the upstream
type tlsHelloConnection struct {
	net.Conn

	// as the doc mentions, net.Conn implementations must be thread-safe
	// (see https://golang.org/pkg/net/#Conn)
	mutex sync.Mutex

	// once the handshake has succeeded, this connection just transparently wraps the underlying net.Conn
	normalOperationMode bool

	// until we switch to normal operation mode, we record bytes written to or read from this connection
	read    []byte
	written []byte
}

func (c *tlsHelloConnection) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)

	if !c.normalOperationMode {
		c.mutex.Lock()
		if !c.normalOperationMode {
			// could have changed while waiting to acquire the lock
			c.read = append(c.read, b[:n]...)
		}
		c.mutex.Unlock()
	}

	return
}

func (c *tlsHelloConnection) Write(b []byte) (n int, err error) {
	if c.normalOperationMode {
		return c.Conn.Write(b)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.normalOperationMode && (len(c.written) != 0 || (len(b) != 0 && b[0] == alertTLSHandshakeAlertRecordHeader)) {
		// the first message from the server back to the client is an alert record
		// that could be simply because we don't have a certificate for the targeted hostname;
		// so we hold off from sending this message, and will let the proxy decide if it wants to send
		// that message, or else establish a non-MitM tunnel instead
		c.written = append(c.written, b...)
		return len(b), nil
	}

	return c.Conn.Write(b)
}

// flushes the written bytes that were previously withheld from the client
func (c *tlsHelloConnection) flushWithheldWrittenBuffer() (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.Conn.Write(c.written)
}

func (c *tlsHelloConnection) resumeNormalOperation() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.normalOperationMode = true
	// we don't care about the buffers going forward
	c.read = nil
	c.written = nil
}

// A oneShotListener is a net.Listener whose Accept only returns a
// net.Conn as specified by c followed by an error for each subsequent Accept.
type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errClosedListener
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// A onCloseConn is a net.Conn that calls its f on Close.
type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}
