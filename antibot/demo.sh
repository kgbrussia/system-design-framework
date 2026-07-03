#!/usr/bin/env bash
# Minimal smoke test of the running server (nonce issuance + health).
# The full envelope flow needs client crypto — see the integration tests
# (FullFlowTest / SdkCoreFlowTest) which exercise it end-to-end.
set -euo pipefail

BASE="${1:-http://localhost:8080}"

echo "== health =="
curl -sS "$BASE/health"; echo

echo "== server public key (use this to configure the SDK) =="
curl -sS "$BASE/v1/pubkey"; echo

echo "== issue a nonce =="
curl -sS -X POST "$BASE/v1/nonce" \
  -H 'Content-Type: application/json' \
  -d '{"sdkVersion":"1.0.0","packageName":"com.example.host"}'; echo

echo
echo "Nonce issued. Sealing an envelope requires the client crypto (EnvelopeCrypto.seal)."
echo "Run 'gradle test' to see the full nonce -> envelope -> attest -> trust token flow."
