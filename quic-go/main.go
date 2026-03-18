package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

const addr = "localhost:4242"

// keyLogWriter returns an io.Writer for TLS key logging if SSLKEYLOGFILE is set.
func keyLogWriter() io.Writer {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("cannot open SSLKEYLOGFILE %q: %v", path, err)
	}
	fmt.Println("writing TLS keys to", path)
	return f
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: quic-echo <server|client>")
	}

	switch os.Args[1] {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		log.Fatalf("unknown command: %s", os.Args[1])
	}
}

// runServer listens for a QUIC connection, accepts a stream, and echoes data.
func runServer() {
	tlsCfg := generateTLSConfig()

	listener, err := quic.ListenAddr(addr, tlsCfg, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Println("server: listening on", addr)

	conn, err := listener.Accept(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("server: accepted connection from", conn.RemoteAddr())

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("server: accepted stream", stream.StreamID())

	n, err := io.Copy(stream, stream)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("server: echoed %d bytes\n", n)

	stream.Close()
}

// runClient dials the server, opens a stream, writes a message, and reads the echo.
func runClient() {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"echo-demo"},
		KeyLogWriter:       keyLogWriter(),
	}

	conn, err := quic.DialAddr(context.Background(), addr, tlsCfg, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.CloseWithError(0, "bye")
	fmt.Println("client: connected to", addr)

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("Hello, QUIC!")
	_, err = stream.Write(message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client: sent %q\n", message)

	// Close the write side so the server's io.Copy finishes.
	stream.Close()

	buf, err := io.ReadAll(stream)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client: received echo %q\n", buf)
}

// generateTLSConfig creates a self-signed TLS config for the server.
func generateTLSConfig() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Echo Demo"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos:   []string{"echo-demo"},
		KeyLogWriter: keyLogWriter(),
	}
}
