#!/usr/bin/env bash
# End-to-end tests for pq-audit M1: chain integrity + tamper detection.
set -u
BIN="${BIN:-./pq-audit}"
fail=0
pass() { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT

# init
"$BIN" init --dir "$D" >/dev/null || bad "init"
[ -f "$D/audit-000000.palog" ] && pass "segment created" || bad "segment created"

# empty verify
"$BIN" verify --dir "$D" >/dev/null && pass "verify empty chain" || bad "verify empty chain"

# append three entries
echo "boot complete"            | "$BIN" log --dir "$D" --src 2 --level 1 >/dev/null || bad "log 1"
echo '{"t":"tids.alert"}'       | "$BIN" log --dir "$D" --src 1 --level 4 >/dev/null || bad "log 2"
printf ''                       | "$BIN" log --dir "$D" --src 3 --level 0 >/dev/null || bad "log 3 (empty payload)"

# verify intact chain -> exit 0, 3 entries
out="$("$BIN" verify --dir "$D")"; rc=$?
[ "$rc" -eq 0 ] && echo "$out" | grep -q "3 entries" && pass "verify intact (3 entries)" \
    || bad "verify intact (rc=$rc: $out)"

# tamper: flip a byte in the middle of the file, expect exit 2
sz=$(stat -c%s "$D/audit-000000.palog")
mid=$(( sz / 2 ))
printf '\x00' | dd of="$D/audit-000000.palog" bs=1 seek="$mid" count=1 conv=notrunc status=none
"$BIN" verify --dir "$D" >/dev/null; rc=$?
[ "$rc" -eq 2 ] && pass "tamper detected (exit 2)" || bad "tamper detected (got rc=$rc)"

# append refuses on a broken chain
echo "x" | "$BIN" log --dir "$D" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && pass "append refused on broken chain" || bad "append refused (got rc=$rc)"

# truncation of the tail is caught
D2="$(mktemp -d)"; trap 'rm -rf "$D" "$D2"' EXIT
"$BIN" init --dir "$D2" >/dev/null
echo "a" | "$BIN" log --dir "$D2" >/dev/null
echo "b" | "$BIN" log --dir "$D2" >/dev/null
truncate -s -10 "$D2/audit-000000.palog"
"$BIN" verify --dir "$D2" >/dev/null; rc=$?
[ "$rc" -eq 2 ] && pass "torn/truncated tail detected" || bad "truncation (got rc=$rc)"

# ---- M2: post-quantum sealing ----
echo
echo "M2 seal tests:"
KD="$(mktemp -d)"; SD="$(mktemp -d)"
trap 'rm -rf "$D" "$D2" "$KD" "$SD"' EXIT

"$BIN" keygen --out "$KD/anchor" --alg ml-dsa-65 >/dev/null 2>&1
if [ ! -f "$KD/anchor.pub" ]; then
    echo "  skip M2 (keygen failed — liboqs unavailable?)"
else
    pass "keygen ml-dsa-65"
    "$BIN" init --dir "$SD" >/dev/null
    echo "boot"             | "$BIN" log --dir "$SD" >/dev/null
    echo '{"alert":true}'   | "$BIN" log --dir "$SD" --src 1 >/dev/null
    "$BIN" seal --dir "$SD" --key "$KD/anchor.key" >/dev/null && pass "seal" || bad "seal"

    out="$("$BIN" verify --dir "$SD" --pub "$KD/anchor.pub")"; rc=$?
    [ "$rc" -eq 0 ] && echo "$out" | grep -q "SEALS OK" && pass "sealed verify OK" \
        || bad "sealed verify (rc=$rc)"

    # wrong key must fail signer-binding
    "$BIN" keygen --out "$KD/other" --alg ml-dsa-65 >/dev/null 2>&1
    "$BIN" verify --dir "$SD" --pub "$KD/other.pub" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] && pass "wrong signer rejected (exit 2)" || bad "wrong signer (rc=$rc)"

    # wholesale rewrite from scratch: chain alone is fooled, seal is not
    rm -f "$SD/audit-000000.palog"
    "$BIN" init --dir "$SD" >/dev/null
    echo "boot"               | "$BIN" log --dir "$SD" >/dev/null
    echo "nothing happened"   | "$BIN" log --dir "$SD" >/dev/null
    "$BIN" verify --dir "$SD" >/dev/null; rc=$?
    [ "$rc" -eq 0 ] && pass "chain-only accepts rewrite (expected M1 limit)" || bad "chain-only rewrite (rc=$rc)"
    "$BIN" verify --dir "$SD" --pub "$KD/anchor.pub" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] && pass "seal rejects wholesale rewrite (exit 2)" || bad "seal rewrite (rc=$rc)"

    # ---- M4: Merkle inclusion proofs (reuse the intact sealed log) ----
    rm -f "$SD/audit-000000.palog" "$SD/audit.seal"
    "$BIN" init --dir "$SD" >/dev/null
    for i in 0 1 2 3 4; do echo "event $i" | "$BIN" log --dir "$SD" >/dev/null; done
    ROOT="$("$BIN" seal --dir "$SD" --key "$KD/anchor.key" | awk -F: '/merkle/{gsub(/ /,"",$2);print $2}')"
    "$BIN" proof --dir "$SD" --seq 3 | "$BIN" check-proof --root "$ROOT" >/dev/null; rc=$?
    [ "$rc" -eq 0 ] && pass "merkle proof verifies (seq 3)" || bad "merkle proof (rc=$rc)"
    "$BIN" proof --dir "$SD" --seq 2 | "$BIN" check-proof \
        --root 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
        >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] && pass "merkle proof rejects wrong root (exit 2)" || bad "merkle wrong root (rc=$rc)"

    # ---- off-box seal sink: survives deletion of the local seal journal ----
    OFFBOX="$KD/offbox.seal"
    "$BIN" seal --dir "$SD" --key "$KD/anchor.key" --sink "$OFFBOX" >/dev/null
    rm -f "$SD/audit.seal"                       # attacker destroys local evidence
    "$BIN" verify --dir "$SD" --pub "$KD/anchor.pub" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 1 ] && pass "local seal gone → nothing to check" || bad "local seal gone (rc=$rc)"
    "$BIN" verify --dir "$SD" --pub "$KD/anchor.pub" --seal-file "$OFFBOX" >/dev/null; rc=$?
    [ "$rc" -eq 0 ] && pass "off-box sink still proves the seal" || bad "off-box verify (rc=$rc)"

    # ---- M3: forward security ----
    "$BIN" fs-init --out "$KD/fs" --alg ml-dsa-65 --anchor slh-dsa-128f --epochs 3 >/dev/null 2>&1
    if [ -f "$KD/fs.fspub" ]; then
        pass "fs-init"
        FD="$(mktemp -d)"; trap 'rm -rf "$D" "$D2" "$KD" "$SD" "$FD"' EXIT
        "$BIN" init --dir "$FD" >/dev/null
        echo "a" | "$BIN" log --dir "$FD" >/dev/null
        echo "b" | "$BIN" log --dir "$FD" >/dev/null
        "$BIN" seal --dir "$FD" --ring "$KD/fs.fsring" >/dev/null && pass "fs seal (epoch 0)" || bad "fs seal"
        "$BIN" verify --dir "$FD" --fspub "$KD/fs.fspub" --anchor "$KD/fs.anchor.pub" >/dev/null; rc=$?
        [ "$rc" -eq 0 ] && pass "fs verify" || bad "fs verify (rc=$rc)"
        "$BIN" fs-advance --ring "$KD/fs.fsring" >/dev/null && pass "fs-advance destroys epoch 0" || bad "fs-advance"
        "$BIN" verify --dir "$FD" --fspub "$KD/fs.fspub" --anchor "$KD/fs.anchor.pub" >/dev/null; rc=$?
        [ "$rc" -eq 0 ] && pass "old seal still verifies after key destroyed" || bad "post-destroy verify (rc=$rc)"
        # tamper the manifest -> anchor rejects
        cp "$KD/fs.fspub" "$KD/fs.bad"
        python3 - "$KD/fs.bad" <<'PY' 2>/dev/null || dd if=/dev/zero of="$KD/fs.bad" bs=1 seek=200 count=1 conv=notrunc status=none
import sys; f=sys.argv[1]; d=bytearray(open(f,'rb').read()); d[200]^=1; open(f,'wb').write(d)
PY
        "$BIN" verify --dir "$FD" --fspub "$KD/fs.bad" --anchor "$KD/fs.anchor.pub" >/dev/null 2>&1; rc=$?
        [ "$rc" -eq 2 ] && pass "anchor rejects tampered manifest (exit 2)" || bad "manifest tamper (rc=$rc)"
    else
        echo "  skip M3 (fs-init failed)"
    fi

    # ---- M5: ingest daemon ----
    echo
    echo "M5 daemon tests:"
    if ! command -v python3 >/dev/null 2>&1; then
        echo "  skip M5 (python3 unavailable)"
    else
        RD="$(mktemp -d)"; SOCK="$RD/s.sock"
        trap 'rm -rf "$D" "$D2" "$KD" "$SD" "$FD" "$RD"' EXIT
        "$BIN" init --dir "$RD" >/dev/null
        "$BIN" run --dir "$RD" --ingest "unix:$SOCK" --key "$KD/anchor.key" \
               --src 7 --seal-every 3 >/dev/null 2>"$RD/d.log" &
        DPID=$!
        for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
        if [ ! -S "$SOCK" ]; then bad "daemon socket came up"; kill $DPID 2>/dev/null; else
            pass "daemon listening on socket"
            python3 - "$SOCK" <<'PY'
import socket,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
for i in range(5): s.sendall(('{"n":%d}\n'%i).encode()); time.sleep(0.03)
s.close(); time.sleep(0.3)
PY
            sleep 0.3
            n="$("$BIN" verify --dir "$RD" | head -1)"
            echo "$n" | grep -q "5 entries" && pass "daemon ingested 5 entries" || bad "daemon ingest ($n)"
            kill -TERM $DPID; wait $DPID 2>/dev/null
            # 5 entries, seal-every 3 → one auto-seal (seq2) + shutdown seal (seq4)
            out="$("$BIN" verify --dir "$RD" --pub "$KD/anchor.pub")"; rc=$?
            [ "$rc" -eq 0 ] && echo "$out" | grep -q "through seq 4" && pass "daemon auto+shutdown seals verify" \
                || bad "daemon seals (rc=$rc: $out)"
        fi
    fi

    # ---- segment rotation: verify spans segments via prev_segment_root ----
    echo
    echo "rotation tests:"
    GD="$(mktemp -d)"; trap 'rm -rf "$D" "$D2" "$KD" "$SD" "$FD" "$RD" "$GD"' EXIT
    "$BIN" init --dir "$GD" >/dev/null
    echo "s0a" | "$BIN" log --dir "$GD" >/dev/null
    echo "s0b" | "$BIN" log --dir "$GD" >/dev/null
    "$BIN" rotate --dir "$GD" >/dev/null && pass "rotate creates new segment" || bad "rotate"
    [ -f "$GD/audit-000001.palog" ] && pass "segment 000001 exists" || bad "segment 000001"
    echo "s1a" | "$BIN" log --dir "$GD" >/dev/null
    echo "s1b" | "$BIN" log --dir "$GD" >/dev/null
    out="$("$BIN" verify --dir "$GD")"; rc=$?
    [ "$rc" -eq 0 ] && echo "$out" | grep -q "4 entries" && pass "verify spans 2 segments (4 entries)" \
        || bad "cross-segment verify (rc=$rc: $out)"
    # seal across the boundary, then prove an entry in the FIRST segment
    ROOT="$("$BIN" seal --dir "$GD" --key "$KD/anchor.key" | awk -F: '/merkle/{gsub(/ /,"",$2);print $2}')"
    "$BIN" verify --dir "$GD" --pub "$KD/anchor.pub" >/dev/null; rc=$?
    [ "$rc" -eq 0 ] && pass "seal verifies over rotated log" || bad "rotated seal verify (rc=$rc)"
    "$BIN" proof --dir "$GD" --seq 1 | "$BIN" check-proof --root "$ROOT" >/dev/null; rc=$?
    [ "$rc" -eq 0 ] && pass "merkle proof for entry in first segment" || bad "cross-seg proof (rc=$rc)"
    # break the linkage: corrupt seg1's prev_segment_root → verify must fail
    python3 -c "f='$GD/audit-000001.palog';d=bytearray(open(f,'rb').read());d[30]^=1;open(f,'wb').write(d)" 2>/dev/null \
        && { "$BIN" verify --dir "$GD" >/dev/null 2>&1; rc=$?; \
             [ "$rc" -eq 2 ] && pass "broken cross-segment link detected (exit 2)" || bad "link tamper (rc=$rc)"; }
fi

echo
[ "$fail" -eq 0 ] && { echo "ALL TESTS PASSED"; exit 0; } || { echo "TESTS FAILED"; exit 1; }
