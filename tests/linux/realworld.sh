#!/bin/bash
# Real AArch64 Linux programs (an Ubuntu arm64 sysroot, see
# tools/linux_sysroot/fetch_sysroot.py) under juice and under qemu-aarch64:
# stdout and exit codes must match. --bench also times heavier workloads.
#
# usage: tests/linux/realworld.sh JUICE SYSROOT [--bench] [filter]
#   fetch_sysroot.py ~/arm64root resolute bash coreutils busybox-static python3-minimal \
#       perl-base grep sed gawk findutils tar gzip xz-utils sqlite3 file diffutils
#   tests/linux/realworld.sh build/linux/x86_64/releasedbg/juice ~/arm64root

JUICE=$(realpath "$1"); ROOT=$(realpath "$2"); shift 2
BENCH=0; [ "$1" = --bench ] && { BENCH=1; shift; }
FILTER=$1
command -v qemu-aarch64 >/dev/null || { echo "qemu-aarch64 is needed as the reference"; exit 2; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; cd "$W"
B=$ROOT/usr/bin
printf 'banana\napple\ncherry\napple\n' > fruit.txt
for i in $(seq 1 200); do echo "line $i $((i * 7919 % 1000))"; done > nums.txt

pass=0; fail=0
run() {
  local name=$1; shift
  [ -n "$FILTER" ] && [[ "$name" != *$FILTER* ]] && return
  [ -x "$1" ] || { printf 'skip  %-28s (%s not in the sysroot)\n' "$name" "${1#$ROOT}"; return; }
  timeout -k 2 60 qemu-aarch64 -L "$ROOT" "$@" > q.out 2> q.err < /dev/null; local qc=$?
  local start=$(date +%s%N)
  timeout -k 2 60 "$JUICE" --sysroot="$ROOT" -- "$@" > j.out 2> j.err < /dev/null; local jc=$?
  local ms=$(( ($(date +%s%N) - start) / 1000000 ))
  if [ $qc -eq $jc ] && cmp -s q.out j.out; then
    pass=$((pass + 1)); printf 'ok    %-28s %6d ms\n' "$name" "$ms"
  else
    fail=$((fail + 1)); printf 'FAIL  %-28s juice=%s qemu=%s\n' "$name" "$jc" "$qc"
    diff <(head -c 2000 q.out) <(head -c 2000 j.out) | head -8 | sed 's/^/        /'
    head -4 j.err | sed 's/^/   err: /'
  fi
}
run busybox-echo      $B/busybox echo hello world
run busybox-sort      $B/busybox sort fruit.txt
run busybox-sh        $B/busybox sh -c 'for i in 1 2 3; do echo $((i*i)); done; echo done'
run busybox-awk       $B/busybox awk '{s+=$3} END {print s}' nums.txt
run busybox-md5       $B/busybox md5sum nums.txt
run busybox-wc        $B/busybox wc nums.txt
run bash-arith        $B/bash -c 'x=0; for ((i=0;i<20000;i++)); do x=$((x+i*i%7)); done; echo $x'
run bash-strings      $B/bash -c 'a="Hello World"; echo ${a,,} ${a^^} ${#a} ${a/World/There}'
run bash-arrays       $B/bash -c 'declare -A m; m[a]=1; m[b]=2; for k in "${!m[@]}"; do echo $k=${m[$k]}; done | sort'
run bash-subshell     $B/bash -c 'echo $(echo nested $(echo deeper)); (exit 3); echo $?'
run bash-pipeline     $B/bash -c 'seq 1 1000 | grep 7 | wc -l'
run gnu-sort          $B/gnusort fruit.txt
run gnu-ls            $B/gnuls -1 $ROOT/etc/skel
run uu-sort           $B/sort -u fruit.txt
run uu-sha256         $B/sha256sum nums.txt
run uu-seq            $B/seq 1 3 30
run uu-date           $B/date -u -d @1000000000 +%Y-%m-%dT%H:%M:%S
run uu-factor         $B/factor 1234567890 600851475143
run grep              $B/grep -c '^line 1' nums.txt
run grep-regex        $B/grep -E 'line (1|2)[0-9]+ [0-9]{3}$' nums.txt
run sed               $B/sed -e 's/line/L/' -e '/L 1/d' nums.txt
run gawk              $B/gawk '{a[$3%10]++} END {for (k=0;k<10;k++) printf "%d ", a[k]; print ""}' nums.txt
run gawk-math         $B/gawk 'BEGIN { printf "%.6f %.6f %d\n", sin(1), exp(2.5), 2^40 }'
run perl              $B/perl -e 'my %h; $h{$_ % 13}++ for 1..10000; print join(",", map {"$_=$h{$_}"} sort {$a<=>$b} keys %h), "\n"'
run perl-regex        $B/perl -ne 'print if /^line \d+ (\d)\1/' nums.txt
PY=$(ls $B/python3.* 2>/dev/null | grep -E 'python3\.[0-9]+$' | head -1)
run python-basic      $PY -c 'print(sum(i*i for i in range(100000)), 2**100, 3.14159**2.5)'
run python-dict       $PY -c 'd={str(i):i for i in range(20000)}; print(len(d), sorted(d)[:3])'
run python-float      $PY -c 'import math; print(math.sqrt(2), math.lgamma(10.5), round(1e-300*1e-10, 400))'
run python-unicode    $PY -c 'print("héllo wörld ✓".upper(), "日本語"[::-1], len("😀".encode()))'
run python-struct     $PY -c 'import struct,zlib; d=struct.pack("<qdf", -5, 2.5, 1.5); print(d.hex(), zlib.crc32(d))'
run python-thread     $PY -c 'import threading; r=[]; ts=[threading.Thread(target=lambda i=i: r.append(i*i)) for i in range(8)]; [t.start() for t in ts]; [t.join() for t in ts]; print(sorted(r))'
run python-subprocess $PY -c 'import subprocess; print(subprocess.run(["echo","sub"],capture_output=True).stdout)'
run tar-gzip          $B/bash -c 'tar czf a.tgz fruit.txt nums.txt && tar tzf a.tgz && gzip -dc a.tgz | wc -c'
run xz                $B/bash -c 'xz -9 -c nums.txt | xz -dc | sha256sum'
run sqlite            $B/sqlite3 :memory: 'create table t(a,b); insert into t values (1,"x"),(2,"y"),(3,"z"); select sum(a), group_concat(b) from t;'
run file              $B/file -m $ROOT/usr/lib/file/magic.mgc $B/bash
run diff              $B/diff fruit.txt nums.txt
echo "passed $pass, failed $fail"

if [ $BENCH = 1 ]; then
  for i in $(seq 1 200000); do echo "line $i $((i * 7919 % 100003)) some text to compress"; done > big.txt
  t() { local s=$(date +%s%N); "$@" > /dev/null 2>&1; echo $(( ($(date +%s%N) - s) / 1000000 )); }
  bench() {
    local name=$1; shift
    [ -x "$1" ] || return
    local q=$(t timeout 300 qemu-aarch64 -L "$ROOT" "$@")
    local j=$(t timeout 300 "$JUICE" --sysroot="$ROOT" -- "$@")
    printf '%-14s qemu %7d ms   juice %7d ms   juice/qemu %s\n' "$name" "$q" "$j" "$(echo "scale=2; $j / $q" | bc)"
  }
  bench python-json  $PY -c 'import json; d=[{"k":i,"v":str(i)*3} for i in range(200000)]; print(len(json.loads(json.dumps(d))))'
  bench python-float $PY -c $'x=0.0\nfor i in range(2000000): x += (i % 7) * 0.5 / (i + 1)\nprint(x)'
  bench perl-loop    $B/perl -e 'my $s=0; for my $i (1..3000000) { $s += $i % 13 } print "$s\n"'
  bench bash-loop    $B/bash -c 'x=0; for ((i=0;i<300000;i++)); do x=$((x+i%7)); done; echo $x'
  bench xz           $B/xz -6 -c big.txt
  bench gzip         $B/gzip -9 -c big.txt
  bench sort         $B/gnusort -k3 -n big.txt
  bench sqlite       $B/sqlite3 :memory: 'with recursive c(x) as (select 1 union all select x+1 from c where x<1000000) select sum(x*x % 97) from c;'
fi
[ $fail = 0 ]
