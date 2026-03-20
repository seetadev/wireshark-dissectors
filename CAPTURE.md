# Capturing Decryptable QUIC Traffic from Ethereum Consensus Clients

## Overview

Ethereum consensus clients (Prysm, Lighthouse, etc.) use libp2p over QUIC for
peer-to-peer networking. QUIC encrypts all traffic with TLS 1.3, making packet
inspection impossible without the session keys.

This document describes how to patch a client to export TLS keys via the
standard `SSLKEYLOGFILE` mechanism, then capture and decrypt the traffic.

## Required go-libp2p Patch

go-libp2p's TLS security module already supports `KeyLogWriter` via
`WithKeyLogWriter()`, but the QUIC transport constructor doesn't pass this
option through. A two-line patch is needed in
`p2p/transport/quic/transport.go`:

```diff
-func NewTransport(key ic.PrivKey, connManager *quicreuse.ConnManager,
-    psk pnet.PSK, gater connmgr.ConnectionGater,
-    rcmgr network.ResourceManager) (tpt.Transport, error) {
+func NewTransport(key ic.PrivKey, connManager *quicreuse.ConnManager,
+    psk pnet.PSK, gater connmgr.ConnectionGater,
+    rcmgr network.ResourceManager,
+    opts ...p2ptls.IdentityOption) (tpt.Transport, error) {
     ...
-    identity, err := p2ptls.NewIdentity(key)
+    identity, err := p2ptls.NewIdentity(key, opts...)
```

This patch has been tested on go-libp2p v0.39.1, v0.47.0, and v0.48.0. Apply
it via a local copy and a `replace` directive in `go.mod`:

```
replace github.com/libp2p/go-libp2p => ./go-libp2p-local
```

## Client-Side Changes

### Prysm

In `beacon-chain/p2p/options.go`, add the key log option to the QUIC transport:

```go
import p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"

func keyLogOption() p2ptls.IdentityOption {
    path := os.Getenv("SSLKEYLOGFILE")
    if path == "" {
        return func(*p2ptls.IdentityConfig) {}
    }
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
    if err != nil {
        return func(*p2ptls.IdentityConfig) {}
    }
    return p2ptls.WithKeyLogWriter(f)
}
```

Then change the transport registration:

```diff
-options = append(options, libp2p.Transport(libp2pquic.NewTransport))
+options = append(options, libp2p.Transport(libp2pquic.NewTransport, keyLogOption()))
```

### Other go-libp2p Clients

The same pattern applies to any Go program using go-libp2p with QUIC: apply
the go-libp2p patch, then pass `keyLogOption()` as an extra argument to
`libp2p.Transport(libp2pquic.NewTransport, ...)`.

## Capture Procedure

The order matters: **start tcpdump before the client** so that all QUIC
handshakes are captured. Without the Initial packets, tshark cannot associate
short-header packets with their TLS keys.

```bash
# 1. Start packet capture on the QUIC port FIRST
tcpdump -i eth0 -w capture.pcap "udp port 13001" &

# 2. Start the client with SSLKEYLOGFILE
SSLKEYLOGFILE=keys.log ./beacon-chain \
    --mainnet \
    --p2p-quic-port=13001 \
    ...

# 3. Wait for traffic, then stop client before tcpdump
kill $CLIENT_PID
sleep 2
kill $TCPDUMP_PID
```

## Decryption with tshark

```bash
tshark -r capture.pcap \
    -o tls.keylog_file:keys.log \
    -d udp.port==13001,quic
```

## Decryption with Wireshark GUI

1. Edit > Preferences > Protocols > TLS
2. Set "(Pre)-Master-Secret log filename" to the `keys.log` path
3. Open the pcap file

## Limitations

- Only connections where **our node participates in the TLS handshake** can be
  decrypted. Traffic between other peers passing through the same network
  segment cannot be decrypted.
- tshark must see the QUIC Initial (handshake) packets to map connection IDs
  to TLS keys. Captures started after connections are established will have
  undecryptable traffic.
- Noise-secured connections (TCP transport) do not produce SSLKEYLOGFILE
  output. Only QUIC connections (which use TLS 1.3) are decryptable.
