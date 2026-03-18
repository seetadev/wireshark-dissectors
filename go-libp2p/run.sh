#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

go build -o libp2p-echo .

tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

# Start the server, tee stdout to a temp file so we can parse the multiaddr.
./libp2p-echo server > >(tee "$tmpfile") 2>&1 &
server_pid=$!

# Wait for the server to print its full addr line.
server_addr=""
for i in $(seq 1 20); do
    sleep 0.25
    server_addr=$(grep -o '/ip4/127\.0\.0\.1/udp/4242/quic-v1/p2p/[^ ]*' "$tmpfile" 2>/dev/null || true)
    if [ -n "$server_addr" ]; then
        break
    fi
done

if [ -z "$server_addr" ]; then
    echo "FAIL: could not get server address" >&2
    kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null || true
    exit 1
fi

echo "run.sh: using server addr: $server_addr"

SERVER_ADDR="$server_addr" ./libp2p-echo client
client_status=$?

kill "$server_pid" 2>/dev/null
wait "$server_pid" 2>/dev/null || true

if [ "$client_status" -eq 0 ]; then
    echo "OK: echo completed successfully"
else
    echo "FAIL: client exited with $client_status" >&2
    exit 1
fi
