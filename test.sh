#!/usr/bin/env bash
# Test that the Wireshark Lua dissectors correctly parse the test captures.
# Requires: tshark
set -euo pipefail

cd "$(dirname "$0")"

pass=0
fail=0

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"

    if [ "$actual" -ge "$expected" ]; then
        echo "  PASS  $desc (got $actual, expected >= $expected)"
        pass=$((pass + 1))
    else
        echo "  FAIL  $desc (got $actual, expected >= $expected)"
        fail=$((fail + 1))
    fi
}

check_zero() {
    local desc="$1"
    local actual="$2"

    if [ "$actual" -eq 0 ]; then
        echo "  PASS  $desc"
        pass=$((pass + 1))
    else
        echo "  FAIL  $desc (got $actual)"
        fail=$((fail + 1))
    fi
}

run_tshark() {
    local pcap="$1"
    local keys="$2"
    shift 2
    tshark -r "$pcap" -o "tls.keylog_file:$keys" -d udp.port==13001,quic \
        -X lua_script:libp2p-identify.lua \
        -X lua_script:libp2p-gossipsub.lua \
        -X lua_script:eth-consensus.lua \
        "$@" 2>&1
}

# ==========================================================================
# Test 1: test.pcap — aggregates, sync contributions, beacon blocks
# ==========================================================================
echo "=== test-data/test.pcap ==="
SUMMARY=$(run_tshark test-data/test.pcap test-data/test-keys.log)
VERBOSE=$(run_tshark test-data/test.pcap test-data/test-keys.log -V)

echo ""
echo "libp2p Identify:"
check "Identify frames" 1 "$(echo "$SUMMARY" | grep -c "LIBP2P-ID" || true)"
check "Identify Message decoded" 1 "$(echo "$VERBOSE" | grep -c "Identify Message" || true)"
check "Agent Version field" 1 "$(echo "$VERBOSE" | grep -c "Agent Version:" || true)"

echo ""
echo "GossipSub:"
check "GossipSub frames" 100 "$(echo "$SUMMARY" | grep -c "GOSSIPSUB" || true)"
check "SUBSCRIBE" 1 "$(echo "$SUMMARY" | grep -c "SUBSCRIBE" || true)"
check "GRAFT" 1 "$(echo "$SUMMARY" | grep -c "GRAFT" || true)"
check "IHAVE" 1 "$(echo "$SUMMARY" | grep -c "IHAVE" || true)"
check "IWANT" 1 "$(echo "$SUMMARY" | grep -c "IWANT" || true)"
check "IDONTWANT" 1 "$(echo "$SUMMARY" | grep -c "IDONTWANT" || true)"
check "PUBLISH" 100 "$(echo "$SUMMARY" | grep -c "PUBLISH" || true)"

echo ""
echo "Ethereum consensus - SignedBeaconBlock:"
check "decoded" 1 "$(echo "$VERBOSE" | grep -c "SignedBeaconBlock" || true)"
check "Proposer Index" 1 "$(echo "$VERBOSE" | grep -c "Proposer Index:" || true)"
check "Block Size" 1 "$(echo "$VERBOSE" | grep -c "Block Size:" || true)"

echo ""
echo "Ethereum consensus - SignedAggregateAttestationAndProof:"
check "decoded" 10 "$(echo "$VERBOSE" | grep -c "SignedAggregateAttestationAndProof" || true)"
check "Aggregator Index" 10 "$(echo "$VERBOSE" | grep -c "Aggregator Index:" || true)"
check "Committee Bits with hex" 10 "$(echo "$VERBOSE" | grep -c "Committee Bits:.*0x" || true)"
check "Aggregation Bits with hex" 10 "$(echo "$VERBOSE" | grep -c "Aggregation Bits:.*0x" || true)"

echo ""
echo "Ethereum consensus - SignedContributionAndProof:"
check "decoded" 1 "$(echo "$VERBOSE" | grep -c "SignedContributionAndProof" || true)"
check "Subcommittee Index" 1 "$(echo "$VERBOSE" | grep -c "Subcommittee Index:" || true)"
check "Sync aggregation bits with hex" 1 "$(echo "$VERBOSE" | grep -c "Aggregation Bits:.*128.*0x" || true)"

echo ""
echo "No errors:"
check_zero "No Lua errors in summary" "$(echo "$SUMMARY" | grep -ci "lua error" || true)"
check_zero "No Lua errors in verbose" "$(echo "$VERBOSE" | grep -ci "lua error" || true)"

# ==========================================================================
# Test 2: test2.pcap — attestations, data column sidecars
# ==========================================================================
echo ""
echo "=== test-data/test2.pcap ==="
SUMMARY2=$(run_tshark test-data/test2.pcap test-data/test2-keys.log)
VERBOSE2=$(run_tshark test-data/test2.pcap test-data/test2-keys.log -V)

echo ""
echo "Ethereum consensus - SingleAttestation:"
check "decoded" 10 "$(echo "$VERBOSE2" | grep -c "SingleAttestation" || true)"
check "Attester Index" 10 "$(echo "$VERBOSE2" | grep -c "Attester Index:" || true)"
check "Beacon Block Root" 10 "$(echo "$VERBOSE2" | grep -c "Beacon Block Root:" || true)"
check "Source checkpoint" 10 "$(echo "$VERBOSE2" | grep -c "Source:" || true)"
check "Target checkpoint" 10 "$(echo "$VERBOSE2" | grep -c "Target:" || true)"

echo ""
echo "Ethereum consensus - DataColumnSidecar:"
check "decoded" 1 "$(echo "$VERBOSE2" | grep -c "DataColumnSidecar" || true)"
check "Column Index" 1 "$(echo "$VERBOSE2" | grep -c "Column Index:" || true)"
check "Sidecar Size" 1 "$(echo "$VERBOSE2" | grep -c "Sidecar Size:" || true)"
check "Signed Block Header" 1 "$(echo "$VERBOSE2" | grep -c "Signed Block Header" || true)"

echo ""
echo "No errors:"
check_zero "No Lua errors in summary" "$(echo "$SUMMARY2" | grep -ci "lua error" || true)"
check_zero "No Lua errors in verbose" "$(echo "$VERBOSE2" | grep -ci "lua error" || true)"

# ==========================================================================
echo ""
echo "========================================="
echo "  $pass passed, $fail failed"
echo "========================================="

[ "$fail" -eq 0 ]
