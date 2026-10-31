//go:build ignore

// h2c-probe stands in for a gRPC backend and client in the NixOS VM test (ADR 0016), standard
// library only, gRPC framing by hand: a compression flag, a 4-byte length, the message.
//
//	h2c-probe server <addr>                        HTTP/1.1 and h2c prior knowledge on one port
//	h2c-probe client <addr> <host> <ca> <silence>  bidi stream through genkan's TLS listener
//
// The server echoes every message of /echo.Echo/Bidi (HTTP/2 only) and ends the call with
// grpc-status 3 in the trailers; any other path answers the request's protocol.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func frame(msg []byte) []byte {
	b := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	return append(b, msg...)
}

func read(r io.Reader) ([]byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint32(head[1:]))
	_, err := io.ReadFull(r, msg)
	return msg, err
}

func server(addr string) error {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	return (&http.Server{Addr: addr, Protocols: p, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/echo.Echo/Bidi" {
			io.WriteString(w, r.Proto)
			return
		}
		if r.ProtoMajor != 2 || r.Header.Get("Te") != "trailers" || r.Header.Get("Content-Type") != "application/grpc" {
			http.Error(w, "not gRPC: "+r.Proto, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			msg, err := read(r.Body)
			if err != nil {
				break
			}
			w.Write(frame(append([]byte("echo:"), msg...)))
			w.(http.Flusher).Flush()
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "3")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "probe")
		w.Header().Set(http.TrailerPrefix+"Grpc-Status-Details-Bin", "CAMSBGRldGFpbA")
	})}).ListenAndServe()
}

func client(addr, host, ca string, silence time.Duration) error {
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	p := new(http.Protocols)
	p.SetHTTP2(true)
	c := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: host, RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}},
		Protocols:       p,
	}}
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", "https://"+addr+"/echo.Echo/Bidi", pr)
	req.Host = host
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.TLS.NegotiatedProtocol != "h2" {
		return fmt.Errorf("%s %s, ALPN %q", res.Proto, res.Status, res.TLS.NegotiatedProtocol)
	}
	for i, msg := range []string{"a", "b", "after-silence"} {
		if i == 2 {
			fmt.Println("silent for", silence)
			time.Sleep(silence)
		}
		if _, err := pw.Write(frame([]byte(msg))); err != nil {
			return err
		}
		if got, err := read(res.Body); err != nil || string(got) != "echo:"+msg {
			return fmt.Errorf("message %q: got %q, %v", msg, got, err)
		}
	}
	pw.Close()
	if _, err := read(res.Body); err != io.EOF {
		return fmt.Errorf("end of stream: %v", err)
	}
	fmt.Printf("ok alpn=%s grpc-status=%s grpc-message=%s grpc-status-details-bin=%s\n", res.TLS.NegotiatedProtocol,
		res.Trailer.Get("Grpc-Status"), res.Trailer.Get("Grpc-Message"), res.Trailer.Get("Grpc-Status-Details-Bin"))
	return nil
}

func main() {
	var err error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "server":
		err = server(os.Args[2])
	case len(os.Args) == 6 && os.Args[1] == "client":
		var silence time.Duration
		if silence, err = time.ParseDuration(os.Args[5]); err == nil {
			err = client(os.Args[2], os.Args[3], os.Args[4], silence)
		}
	default:
		err = fmt.Errorf("usage: h2c-probe server <addr> | client <addr> <host> <ca> <silence>")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
