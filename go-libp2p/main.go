package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/multiformats/go-multiaddr"
)

const (
	echoProtocol = "/echo/1"
	listenAddr   = "/ip4/127.0.0.1/udp/4242/quic-v1"
	topicName    = "test/hello"
)

func keyLogOption() p2ptls.IdentityOption {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return func(*p2ptls.IdentityConfig) {}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("cannot open SSLKEYLOGFILE %q: %v", path, err)
	}
	fmt.Println("writing TLS keys to", path)
	return p2ptls.WithKeyLogWriter(f)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: libp2p-echo <server|client>")
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

// setupGossipSub creates a GossipSub router, joins the topic, and returns
// the topic and subscription handles.
func setupGossipSub(ctx context.Context, h host.Host) (*pubsub.Topic, *pubsub.Subscription) {
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		log.Fatal(err)
	}
	topic, err := ps.Join(topicName)
	if err != nil {
		log.Fatal(err)
	}
	sub, err := topic.Subscribe()
	if err != nil {
		log.Fatal(err)
	}
	return topic, sub
}

func runServer() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.Transport(libp2pquic.NewTransport, keyLogOption()),
		libp2p.DisableRelay(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	// Echo stream handler
	h.SetStreamHandler(echoProtocol, func(s network.Stream) {
		fmt.Println("server: accepted echo stream from", s.Conn().RemotePeer())
		n, err := io.Copy(s, s)
		if err != nil {
			log.Println("server: echo error:", err)
		}
		fmt.Printf("server: echoed %d bytes\n", n)
		s.Close()
	})

	// GossipSub
	topic, sub := setupGossipSub(ctx, h)

	// Read incoming pubsub messages in the background
	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			if msg.ReceivedFrom == h.ID() {
				continue
			}
			fmt.Printf("server: pubsub received %q from %s\n", msg.Data, msg.ReceivedFrom)
		}
	}()

	fmt.Println("server: listening on", h.Addrs())
	fmt.Println("server: peer ID", h.ID())

	for _, addr := range h.Addrs() {
		full := fmt.Sprintf("%s/p2p/%s", addr, h.ID())
		fmt.Println("server: full addr", full)
	}

	// Publish a message once a peer joins the topic mesh
	go func() {
		for {
			if len(topic.ListPeers()) > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		// Give the remote subscriber time to fully set up
		time.Sleep(500 * time.Millisecond)
		data := []byte("Hello from server via GossipSub!")
		if err := topic.Publish(ctx, data); err != nil {
			log.Println("server: publish error:", err)
			return
		}
		fmt.Printf("server: pubsub published %q\n", data)
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	fmt.Println("server: shutting down")
}

func runClient() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
		libp2p.Transport(libp2pquic.NewTransport, keyLogOption()),
		libp2p.DisableRelay(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		log.Fatal("set SERVER_ADDR to the server's full multiaddr")
	}

	ma, err := multiaddr.NewMultiaddr(serverAddr)
	if err != nil {
		log.Fatalf("invalid multiaddr: %v", err)
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		log.Fatalf("invalid peer addr: %v", err)
	}

	if err := h.Connect(ctx, *info); err != nil {
		log.Fatalf("connect: %v", err)
	}
	fmt.Println("client: connected to", info.ID)

	// GossipSub
	topic, sub := setupGossipSub(ctx, h)

	// Wait for mesh to form
	for i := 0; i < 50; i++ {
		if len(topic.ListPeers()) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Let the mesh stabilize
	time.Sleep(500 * time.Millisecond)

	// Publish a message from the client
	data := []byte("Hello from client via GossipSub!")
	if err := topic.Publish(ctx, data); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client: pubsub published %q\n", data)

	// Wait for the server's message
	recvCtx, recvCancel := context.WithTimeout(ctx, 5*time.Second)
	defer recvCancel()
	for {
		msg, err := sub.Next(recvCtx)
		if err != nil {
			fmt.Println("client: pubsub timeout waiting for server message")
			break
		}
		if msg.ReceivedFrom == h.ID() {
			continue
		}
		fmt.Printf("client: pubsub received %q from %s\n", msg.Data, msg.ReceivedFrom)
		break
	}

	// Echo exchange (same as before)
	s, err := h.NewStream(ctx, info.ID, echoProtocol)
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}

	message := []byte("Hello, QUIC!")
	_, err = s.Write(message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client: sent %q\n", message)

	s.CloseWrite()

	buf, err := io.ReadAll(s)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client: received echo %q\n", buf)
	s.Close()
}
