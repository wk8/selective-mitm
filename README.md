[![Build Status](https://travis-ci.com/wk8/selective-mitm.svg?branch=master)](https://travis-ci.com/wk8/selective-mitm)

# go-selective-mitm

SSL-capable selective man-in-the-middle proxy as a Golang library; by selective we mean that you decide which requests get man-in-the-middle'd, which don't, and which certificates to use for those that do.

## Why?

This library addresses a fairly specific use case:
* you want to inspect or modify HTTPS requests made from service A to service B
* you have a valid SSL certificate for service B
* you can configure service A to use a HTTP proxy
* service A makes HTTPS requests to other services than B, that you don't have valid SSL certs for
* you don't want (or cannot) make service A trust a self-signed CA (that you could use to MitM all of its requests, by generating certs on the fly)

Then you can use this library to create a HTTP proxy that will only man-in-the-middle HTTPS requests addressed to those services you have valid SSL certs for; and otherwise behave like a "normal" HTTP proxy for other HTTPS requests, that is create a tunnel.

## Usage

Example program:

```go
package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"

	selective_mitm "github.com/wk8/selective-mitm"
)

// to examine responses
type writerWrapper struct {
	http.ResponseWriter

	code int
}

func (w *writerWrapper) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
	w.code = code
}

// could also define eg
// `func (w *writerWrapper) Write([]byte) (int, error)`
// to examine response bodies

func main() {
	cert, err := tls.LoadX509KeyPair("/path/to/cert/for/my.site.com",
		"/path/to/key/for/my.site.com")
	if err != nil {
		panic(err)
	}

	proxy := &selective_mitm.MITMProxy{
		GetCertificate: func(request *http.Request, info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if info.ServerName == "my.site.com" {
				return &cert, nil
			}

			// don't man-in-the-middle any other request
			return nil, selective_mitm.ErrNoCertificate
		},
		Wrap: func(upstream *httputil.ReverseProxy) http.Handler {
			return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				// you can forward upstream, and examine the response...
				if forwardUpstream(request) {
					wrapper := &writerWrapper{ResponseWriter: writer}
					upstream.ServeHTTP(wrapper, request)

					// examine response status code
					if wrapper.code != http.StatusOK {
						// do something
					}
				} else {
					// ... or else decide to answer the request yourself,
					// without even hitting upstream
					writer.WriteHeader(http.StatusForbidden)
					writer.Write([]byte("can't do this"))
				}
			})
		},
	}

	if err := http.ListenAndServe(":8080", proxy); err != nil {
		panic(err)
	}
}

func forwardUpstream(request *http.Request) bool {
    // your logic here
}
```

## Credit

Heavily inspired from [kr/mitm](https://github.com/kr/mitm); but that library doesn't provide a way to do selective MitM, and forces clients to trust a self-signed CA.
