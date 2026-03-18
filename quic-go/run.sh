#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

go build -o quic-echo .

./quic-echo server &
server_pid=$!

sleep 1

./quic-echo client
client_status=$?

wait "$server_pid"
server_status=$?

if [ "$client_status" -eq 0 ] && [ "$server_status" -eq 0 ]; then
    echo "OK: both server and client exited cleanly"
else
    echo "FAIL: server=$server_status client=$client_status" >&2
    exit 1
fi
