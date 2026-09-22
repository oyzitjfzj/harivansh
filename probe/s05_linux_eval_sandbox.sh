#!/usr/bin/env bash
set -euo pipefail

: "${S05_PROBE_IMAGE:?S05_PROBE_IMAGE is required}"

prefix="noerith-s05-discovery-${GITHUB_RUN_ID:-manual}"
created=()

cleanup() {
  for name in "${created[@]:-}"; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

create_profile() {
  local name="$1"
  shift
  created+=("$name")
  docker create \
    --name "$name" \
    --pull=never \
    --network=none \
    --cgroupns=private \
    --ipc=private \
    --shm-size=33554432b \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges=true \
    --security-opt=seccomp=builtin \
    --user=65532:65532 \
    --memory=134217728b \
    --memory-swap=134217728b \
    --cpus=0.750 \
    --pids-limit=64 \
    --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=33554432,mode=0700,uid=65532,gid=65532 \
    --tmpfs=/work:rw,noexec,nosuid,nodev,size=33554432,mode=0700,uid=65532,gid=65532 \
    --workdir=/work \
    "$S05_PROBE_IMAGE" "$@" >/dev/null
}

assert_absent() {
  local name="$1"
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    echo "container cleanup failed: $name" >&2
    exit 90
  fi
}

success_name="${prefix}-success"
create_profile "$success_name" sh -c '
  set -eu
  test "$(id -u)" = "65532"
  test "$(id -g)" = "65532"
  grep -Eq "^CapEff:[[:space:]]+0+$" /proc/self/status
  grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status

  for path in /noerith-root-write-probe /etc/noerith-write-probe /var/tmp/noerith-write-probe /run/noerith-write-probe; do
    if touch "$path" 2>/dev/null; then
      echo "unexpected writable root path: $path" >&2
      exit 21
    fi
  done

  touch /tmp/noerith-tmp-ok
  touch /work/noerith-work-ok
  touch /dev/shm/noerith-shm-ok

  cp /bin/true /work/noerith-exec-probe
  chmod 0700 /work/noerith-exec-probe
  if /work/noerith-exec-probe >/dev/null 2>&1; then
    echo "/work noexec was not effective" >&2
    exit 22
  fi

  if env | grep -Eq "^(GITHUB_|ACTIONS_)"; then
    echo "host CI environment leaked into container" >&2
    exit 23
  fi

  if getent hosts example.com >/dev/null 2>&1; then
    echo "external name resolution unexpectedly available" >&2
    exit 24
  fi

  printf "UID=%s GID=%s\n" "$(id -u)" "$(id -g)"
  grep -E "^(CapEff|NoNewPrivs):" /proc/self/status
  printf "CGROUP_PIDS_MAX="; cat /sys/fs/cgroup/pids.max
  printf "CGROUP_MEMORY_MAX="; cat /sys/fs/cgroup/memory.max
  printf "CGROUP_MEMORY_SWAP_MAX="; cat /sys/fs/cgroup/memory.swap.max
  printf "CGROUP_CPU_MAX="; cat /sys/fs/cgroup/cpu.max
  printf "TMP_MOUNT="; findmnt -n -o OPTIONS /tmp 2>/dev/null || grep " /tmp " /proc/mounts
  printf "WORK_MOUNT="; findmnt -n -o OPTIONS /work 2>/dev/null || grep " /work " /proc/mounts
  printf "SHM_MOUNT="; findmnt -n -o OPTIONS /dev/shm 2>/dev/null || grep " /dev/shm " /proc/mounts
'

echo "SUCCESS_HOST_CONFIG=$(docker inspect "$success_name" --format '{{json .HostConfig}}')"
echo "SUCCESS_MOUNTS=$(docker inspect "$success_name" --format '{{json .Mounts}}')"
timeout 30s docker start -a "$success_name"
docker rm "$success_name" >/dev/null
assert_absent "$success_name"

pid_name="${prefix}-pid"
create_profile "$pid_name" sh -c '
  i=0
  while [ "$i" -lt 96 ]; do
    sleep 2 &
    i=$((i + 1))
  done
  wait
'
set +e
timeout 30s docker start -a "$pid_name"
pid_start_rc=$?
set -e
pid_exit="$(docker inspect "$pid_name" --format '{{.State.ExitCode}}')"
echo "PID_START_RC=$pid_start_rc"
echo "PID_EXIT_CODE=$pid_exit"
if [ "$pid_exit" = "0" ]; then
  echo "PID pressure unexpectedly completed without hitting the configured limit" >&2
  exit 31
fi
docker rm "$pid_name" >/dev/null
assert_absent "$pid_name"

memory_name="${prefix}-memory"
create_profile "$memory_name" sh -c '
  set -eu
  command -v head >/dev/null
  command -v tr >/dev/null
  x=$(head -c 201326592 /dev/zero | tr "\000" x)
  echo "MEMORY_PRESSURE_UNEXPECTED_SUCCESS=${#x}" >&2
  exit 41
'
set +e
timeout 45s docker start -a "$memory_name"
memory_start_rc=$?
set -e
memory_oom="$(docker inspect "$memory_name" --format '{{.State.OOMKilled}}')"
memory_exit="$(docker inspect "$memory_name" --format '{{.State.ExitCode}}')"
echo "MEMORY_START_RC=$memory_start_rc"
echo "MEMORY_OOM_KILLED=$memory_oom"
echo "MEMORY_EXIT_CODE=$memory_exit"
if [ "$memory_oom" != "true" ]; then
  echo "memory pressure was not stopped by the memory cgroup" >&2
  exit 32
fi
docker rm "$memory_name" >/dev/null
assert_absent "$memory_name"

failure_name="${prefix}-failure"
create_profile "$failure_name" sh -c 'exit 42'
set +e
docker start -a "$failure_name"
failure_start_rc=$?
set -e
failure_exit="$(docker inspect "$failure_name" --format '{{.State.ExitCode}}')"
echo "FAILURE_START_RC=$failure_start_rc"
echo "FAILURE_EXIT_CODE=$failure_exit"
test "$failure_exit" = "42"
docker rm "$failure_name" >/dev/null
assert_absent "$failure_name"

kill_name="${prefix}-kill"
create_profile "$kill_name" sh -c 'sleep 60'
docker start "$kill_name" >/dev/null
sleep 1
docker kill "$kill_name" >/dev/null
kill_exit="$(docker inspect "$kill_name" --format '{{.State.ExitCode}}')"
echo "KILL_EXIT_CODE=$kill_exit"
test "$kill_exit" = "137"
docker rm "$kill_name" >/dev/null
assert_absent "$kill_name"

trap - EXIT

echo "S05_PROFILE_MEMORY_BYTES=134217728"
echo "S05_PROFILE_MEMORY_SWAP_BYTES=134217728"
echo "S05_PROFILE_CPU_MILLIS=750"
echo "S05_PROFILE_PIDS=64"
echo "S05_PROFILE_TMPFS_BYTES=33554432"
echo "S05_PROFILE_UID=65532"
echo "S05_PROFILE_GID=65532"
echo "S05_LINUX_EVAL_SANDBOX_DISCOVERY=PASS"
