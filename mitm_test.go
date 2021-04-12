package selective_mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMITMProxy(t *testing.T) {
	serverCertificate := getServerCertificate(t)

	// a simple upstream server to test our proxy against
	upstream := chi.NewRouter()
	upstream.Get("/ping", func(writer http.ResponseWriter, request *http.Request) {
		_, err := writer.Write([]byte("pong"))
		require.NoError(t, err)
	})

	// let's start a plain HTTP version of it
	upstreamHTTPServer, upstreamHTTPServerClose := startHTTPServer(t, upstream, nil)
	defer upstreamHTTPServerClose()
	// as well as an HTTP version of it
	upstreamHTTPSServer, upstreamHTTPSServerClose := startHTTPServer(t, upstream, serverCertificate)
	defer upstreamHTTPSServerClose()

	// sanity check: we should be able to hit upstreams directly
	for baseURL, httpClient := range map[string]*http.Client{
		localhostHTTPBaseURL(upstreamHTTPServer):   nil,
		localhostHTTPSBaseURL(upstreamHTTPSServer): httpClient(t, withCA()),
	} {
		response, body := makeGETRequest(t, httpClient, baseURL, "ping")
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, "pong", body)
		assert.Equal(t, "", response.Header.Get("x-proxied"))
	}

	t.Run("for plain HTTP requests, it invokes the given HTTP wrapper", func(t *testing.T) {
		// a proxy with no cert info
		proxy := &MITMProxy{
			Wrap: func(upstream *httputil.ReverseProxy) http.Handler {
				return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					writer.Header().Add("x-proxied", "coucou")
					upstream.ServeHTTP(writer, request)
				})
			},
		}
		proxyServer, proxyServerClose := startHTTPServer(t, proxy, nil)
		defer proxyServerClose()

		response, body := makeGETRequest(t, httpClient(t, withProxy(proxyServer)), localhostHTTPBaseURL(upstreamHTTPServer), "ping")
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, "pong", body)
		assert.Equal(t, "coucou", response.Header.Get("x-proxied"))
	})

	t.Run("for HTTPS requests going to a host it has a certificate for, it allows to MitM the request/response", func(t *testing.T) {
		proxy := &MITMProxy{
			GetCertificate: func(request *http.Request, info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return serverCertificate, nil
			},
			Wrap: func(upstream *httputil.ReverseProxy) http.Handler {
				return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					writer.Header().Add("x-proxied", "coucou")
					upstream.ServeHTTP(writer, request)
				})
			},
			TLSClientConfig: tlsConfig(t),
			ConnectErrorLogger: func(err error) {
				t.Fatalf("should not be called")
			},
		}
		proxyServer, proxyServerClose := startHTTPServer(t, proxy, nil)
		defer proxyServerClose()

		response, body := makeGETRequest(t, httpClient(t, withCA(), withProxy(proxyServer)), localhostHTTPSBaseURL(upstreamHTTPSServer), "ping")
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, "pong", body)
		assert.Equal(t, "coucou", response.Header.Get("x-proxied"))
	})

	t.Run("for HTTPS requests going to hosts it doesn't have a certificate for, it tunnels the connection like a normal proxy", func(t *testing.T) {
		proxy := &MITMProxy{
			GetCertificate: func(request *http.Request, info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, ErrNoCertificate
			},
			Wrap: func(upstream *httputil.ReverseProxy) http.Handler {
				t.Fatal("should not be called")
				return nil
			},
			ConnectErrorLogger: func(err error) {
				t.Fatalf("should not be called")
			},
		}
		proxyServer, proxyServerClose := startHTTPServer(t, proxy, nil)
		defer proxyServerClose()

		response, body := makeGETRequest(t, httpClient(t, withCA(), withProxy(proxyServer)), localhostHTTPSBaseURL(upstreamHTTPSServer), "ping")
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, "pong", body)
		assert.Equal(t, "", response.Header.Get("x-proxied"))
	})

	t.Run("if the upstream times out while establishing the connection, it surfaces the error", func(t *testing.T) {
		var connectError error

		proxy := &MITMProxy{
			UpstreamConnectTimeout: 10 * time.Millisecond,
			ConnectErrorLogger: func(err error) {
				connectError = err
			},
		}
		proxyServer, proxyServerClose := startHTTPServer(t, proxy, nil)
		defer proxyServerClose()

		// courtesy of https://stackoverflow.com/questions/100841/artificially-create-a-connection-timeout-error/904609#904609
		_, err := httpClient(t, withProxy(proxyServer)).Get("https://10.255.255.1")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Service Unavailable")
		}

		if assert.Error(t, connectError) {
			assert.Contains(t, connectError.Error(), "i/o timeout")
		}
	})

	t.Run("it gracefully handles errors when doing the TLS handshake with the client", func(t *testing.T) {
		proxy := &MITMProxy{
			GetCertificate: func(request *http.Request, info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, errors.New("dummy error")
			},
			Wrap: func(upstream *httputil.ReverseProxy) http.Handler {
				t.Fatal("should not be called")
				return nil
			},
			ConnectErrorLogger: func(err error) {
				t.Fatalf("should not be called")
			},
		}
		proxyServer, proxyServerClose := startHTTPServer(t, proxy, nil)
		defer proxyServerClose()

		_, err := httpClient(t, withCA(), withProxy(proxyServer)).Get(localhostHTTPSBaseURL(upstreamHTTPSServer) + "/ping")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "remote error: tls: internal error")
		}
	})
}

// Test helpers

// if passed a certificate, will use that to listen for HTTPS requests instead of plain HTTP
// also returns a function to close the server when done with testing
func startHTTPServer(t *testing.T, handler http.Handler, cert *tls.Certificate) (*http.Server, func()) {
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	if cert != nil {
		listener = tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{*cert},
			// disable HTTP/2, see https://github.com/golang/go/issues/14797#issuecomment-196103814
			NextProtos: []string{"http/1.1"},
		})
	}

	server := &http.Server{
		Addr:    listener.Addr().String(),
		Handler: handler,
	}

	go func() {
		defer listener.Close()

		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			require.NoError(t, err)
		}
	}()

	return server, func() {
		require.NoError(t, server.Shutdown(context.Background()))
	}
}

func makeGETRequest(t *testing.T, client *http.Client, urlParts ...string) (*http.Response, string) {
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Get(strings.Join(urlParts, "/"))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, response.Body.Close())
	}()

	body, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)
	return response, string(body)
}

func localhostHTTPBaseURL(server *http.Server) string {
	return localhostBaseURL("http", server)
}

func localhostHTTPSBaseURL(server *http.Server) string {
	return localhostBaseURL("https", server)
}

func localhostBaseURL(protocol string, server *http.Server) string {
	split := strings.Split(server.Addr, ":")
	return fmt.Sprintf("%s://localhost:%s", protocol, split[len(split)-1])
}

type transportPatch func(t *testing.T, transport *http.Transport)

func httpClient(t *testing.T, transportPatches ...transportPatch) *http.Client {
	return patchHTTPClient(t, nil, transportPatches...)
}

func patchHTTPClient(t *testing.T, client *http.Client, transportPatches ...transportPatch) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}

	var transport *http.Transport

	if client.Transport == nil {
		transport = &http.Transport{}
		client.Transport = transport
	} else {
		var ok bool
		transport, ok = client.Transport.(*http.Transport)
		require.True(t, ok)
	}

	for _, patch := range transportPatches {
		patch(t, transport)
	}

	return client
}

func withCA() transportPatch {
	return func(t *testing.T, transport *http.Transport) {
		transport.TLSClientConfig = tlsConfig(t)
	}
}

func withProxy(proxyServer *http.Server) transportPatch {
	return func(t *testing.T, transport *http.Transport) {
		proxyURL, err := url.Parse(localhostHTTPBaseURL(proxyServer))
		require.NoError(t, err)
		transport.Proxy = http.ProxyURL(proxyURL)
	}
}
