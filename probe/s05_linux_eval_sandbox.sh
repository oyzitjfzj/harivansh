#!/usr/bin/env bash
set -euo pipefail

: "${S05_PROBE_IMAGE:?S05_PROBE_IMAGE is required}"

name="noerith-s05-qual-${GITHUB_RUN_ID:-manual}"
input_dir="$(mktemp -d)"
export_dir="$(mktemp -d)"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  chmod -R u+w "$input_dir" "$export_dir" >/dev/null 2>&1 || true
  rm -rf "$input_dir" "$export_dir"
}
trap cleanup EXIT

cat >"$input_dir/main.rs" <<'RS'
fn main() {
    println!("sandbox-ok");
}
RS
chmod 0444 "$input_dir/main.rs"
chmod 0555 "$input_dir"
input_digest="$(sha256sum "$input_dir/main.rs" | awk '{print $1}')"

start_ns="$(date +%s%N)"

docker create \
  --name "$name" \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --memory 1g \
  --memory-swap 1g \
  --cpus 0.5 \
  --ulimit nofile=256:256 \
  --user 65532:65532 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  --tmpfs /work:rw,nosuid,nodev,exec,size=256m \
  --mount type=bind,src="$input_dir",dst=/input,readonly \
  "$S05_PROBE_IMAGE" \
  sh -c '
    set -eu

    test "$(id -u)" = "65532"
    grep -Eq "^CapEff:[[:space:]]+0+$" /proc/self/status
    grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status

    if touch /noerith-root-write-probe 2>/dev/null; then
      echo "root filesystem unexpectedly writable" >&2
      exit 21
    fi

    if touch /input/forbidden-write 2>/dev/null; then
      echo "read-only input mount unexpectedly writable" >&2
      exit 22
    fi

    touch /tmp/noerith-tmp-ok
    touch /work/noerith-work-ok

    if env | grep -Eq "^(GITHUB_|ACTIONS_)"; then
      echo "host CI environment leaked into sandbox" >&2
      exit 23
    fi

    if getent hosts example.com >/dev/null 2>&1; then
      echo "external name resolution unexpectedly available" >&2
      exit 24
    fi

    rustc /input/main.rs -o /work/hello
    /work/hello > /work/result.txt
    test "$(cat /work/result.txt)" = "sandbox-ok"

    echo "UID=$(id -u)"
    grep -E "^(CapEff|NoNewPrivs):" /proc/self/status
    printf "CGROUP_PIDS_MAX="
    cat /sys/fs/cgroup/pids.max
    printf "CGROUP_MEMORY_MAX="
    cat /sys/fs/cgroup/memory.max
    printf "CGROUP_CPU_MAX="
    cat /sys/fs/cgroup/cpu.max
    rustc --version
  '

echo "HOST_CONFIG=$(docker inspect "$name" --format '{{json .HostConfig}}')"
echo "MOUNTS=$(docker inspect "$name" --format '{{json .Mounts}}')"

timeout 30s docker start -a "$name"

docker cp "$name:/work/result.txt" "$export_dir/result.txt"
test "$(cat "$export_dir/result.txt")" = "sandbox-ok"
output_digest="$(sha256sum "$export_dir/result.txt" | awk '{print $1}')"

end_ns="$(date +%s%N)"
elapsed_ms="$(( (end_ns - start_ns) / 1000000 ))"

docker rm "$name" >/dev/null
if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
  echo "container cleanup failed" >&2
  exit 25
fi

chmod -R u+w "$input_dir" "$export_dir"
rm -rf "$input_dir" "$export_dir"
trap - EXIT

echo "INPUT_SHA256=$input_digest"
echo "OUTPUT_SHA256=$output_digest"
echo "ELAPSED_MS=$elapsed_ms"
echo "S05_LINUX_EVAL_SANDBOX_QUALIFICATION: PASS"
