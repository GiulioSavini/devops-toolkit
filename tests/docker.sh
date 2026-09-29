#!/usr/bin/env bash
# Validates baselines/docker/*:
#   1. hadolint on the Dockerfile
#   2. daemon.json parsed by the REAL daemon config parser (dockerd --validate),
#      with a deliberately broken config as a control so a silently-accepting
#      validator cannot make this test vacuous
#   3. the example image is actually built and run with the flags documented in
#      guides/docker-security.md, and the container is then asked FROM INSIDE
#      what the kernel gave it: uid, capability bounding set, read-only rootfs,
#      writable tmpfs
#   4. negative controls: the same image run WITHOUT --read-only, WITHOUT
#      --cap-drop ALL and with --user 0 must report the opposite, which is what
#      proves every assertion above can fail
#
# Requires only bash, curl and a working docker daemon; every tool runs from a
# digest-pinned image. Image digests below were current on 2026-09-28.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_DIR="$ROOT_DIR/baselines/docker"

# hadolint/hadolint:v2.15.1
HADOLINT_IMAGE="hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d"
# docker:29.8.1-dind — the dind variant, because it is the one that ships dockerd
# itself (the plain -cli variant does not, and `--entrypoint dockerd` would fail
# with "executable file not found").
DIND_IMAGE="docker@sha256:3f3c01aaaebf7cce837356b688b7c059a4749f10bd7660dec7c58fc454a283f0"
# ghcr.io/jqlang/jq:1.8.1
JQ_IMAGE="ghcr.io/jqlang/jq@sha256:4f34c6d23f4b1372ac789752cc955dc67c2ae177eb1b5860b75cdc5091ce6f91"

IMAGE_TAG="devops-toolkit/example-app:test-$$"
CONTAINER_NAME="docker-baseline-test-$$"
PORT=18080
TMP_DIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker rmi -f "$IMAGE_TAG" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_eq() {
  local what="$1" expected="$2" actual="$3"
  if [[ "$expected" != "$actual" ]]; then
    fail "$what: expected '$expected', got '$actual'"
  fi
  echo "    ok: $what = $actual"
}

assert_ne() {
  local what="$1" unexpected="$2" actual="$3"
  if [[ "$unexpected" == "$actual" ]]; then
    fail "$what: expected anything other than '$unexpected', got exactly that"
  fi
  echo "    ok: $what = $actual (not '$unexpected')"
}

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || fail "docker CLI not found — this test builds and runs containers, it cannot be skipped into passing"
command -v curl >/dev/null 2>&1 || fail "curl not found"
docker info >/dev/null 2>&1 || fail "cannot reach a docker daemon (docker info failed)"

# ---------------------------------------------------------------------------
# 1. hadolint
# ---------------------------------------------------------------------------
echo "==> hadolint: baselines/docker/Dockerfile"
docker run --rm -i "$HADOLINT_IMAGE" < "$DOCKER_DIR/Dockerfile"

# ---------------------------------------------------------------------------
# 2. daemon.json
# ---------------------------------------------------------------------------
echo "==> jq: baselines/docker/daemon.json is syntactically valid JSON"
# `jq empty` parses the document and emits nothing; do NOT add -e, which turns
# "no output" into exit code 4 and makes this check fail on valid JSON.
docker run --rm -v "$DOCKER_DIR:/cfg:ro" "$JQ_IMAGE" empty /cfg/daemon.json

echo "==> dockerd --validate: baselines/docker/daemon.json"
# `dockerd --validate --config-file=...` parses the file with the daemon's own
# config loader and exits without starting anything, so it catches an unknown
# key or a wrong type (the two mistakes that otherwise surface as a daemon that
# refuses to start after a reboot). The flag has existed since Docker 20.10.
docker run --rm -v "$DOCKER_DIR:/cfg:ro" --entrypoint dockerd "$DIND_IMAGE" \
  --validate --config-file=/cfg/daemon.json

echo "==> control: dockerd --validate must REJECT a broken daemon.json"
# icc is a bool; a string here must be refused. If this passes, the validator
# above is not validating anything and the check above means nothing.
printf '{"icc": "not-a-bool"}\n' > "$TMP_DIR/daemon-broken.json"
if docker run --rm -v "$TMP_DIR:/cfg:ro" --entrypoint dockerd "$DIND_IMAGE" \
  --validate --config-file=/cfg/daemon-broken.json >/dev/null 2>&1; then
  fail "dockerd --validate accepted a daemon.json with a wrong value type — the validation above proves nothing"
fi
echo "    ok: broken config rejected"

# ---------------------------------------------------------------------------
# 3. build and run with the documented hardened flags
# ---------------------------------------------------------------------------
echo "==> docker build: baselines/docker/Dockerfile"
docker build -q -t "$IMAGE_TAG" -f "$DOCKER_DIR/Dockerfile" "$DOCKER_DIR" >/dev/null

echo "==> image metadata"
assert_eq "image runs as non-root by default (Config.User)" "65532:65532" \
  "$(docker image inspect "$IMAGE_TAG" --format '{{.Config.User}}')"

# Starts the example image on $PORT with the given extra flags and waits for it
# to answer. Any previous container with the same name is removed first.
start_app() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER_NAME" \
    -p "127.0.0.1:$PORT:8080" \
    "$@" "$IMAGE_TAG" >/dev/null
  local i
  for i in $(seq 1 40); do
    if curl -sf -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "container did not answer on 127.0.0.1:$PORT within 20s; logs:" >&2
  docker logs "$CONTAINER_NAME" >&2 || true
  fail "container never became reachable"
}

# Asks the container about its own kernel-enforced state. `docker inspect` only
# reports what was REQUESTED; these answers come from inside the namespace, and
# on a distroless image there is no shell to exec into, so this is the only way
# to ask at all.
probe() {
  curl -sf -m 5 "http://127.0.0.1:$PORT/$1" || fail "probe /$1 failed"
}

echo "==> docker run: the hardened flags from guides/docker-security.md"
start_app \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --pids-limit 128 \
  --memory 64m \
  --cpus 0.5

echo "==> assertions from inside the container"
assert_eq "serves HTTP"                 "ok"                  "$(probe healthz)"
assert_eq "runs as the nonroot uid/gid" "uid=65532 gid=65532"  "$(probe whoami)"
assert_eq "root filesystem"             "read-only"            "$(probe rootfs)"
assert_eq "explicit tmpfs at /tmp"      "writable"             "$(probe tmpfs)"
# The BOUNDING set is the one that matters: a non-root process has an empty
# EFFECTIVE set even without --cap-drop, so asserting on CapEff would pass on an
# unhardened container too. An empty bounding set means nothing in this
# container can ever acquire a capability.
# NoNewPrivs=1 is the kernel side of --security-opt no-new-privileges:true; a
# flag that was accepted but not applied shows up here as 0.
assert_eq "capability sets and no_new_privs" \
          "CapBnd=0000000000000000 CapEff=0000000000000000 NoNewPrivs=1" \
          "$(probe caps)"

echo "==> assertions from the daemon's view of the same container"
assert_eq "HostConfig.ReadonlyRootfs" "true"    "$(docker inspect "$CONTAINER_NAME" --format '{{.HostConfig.ReadonlyRootfs}}')"
assert_eq "HostConfig.CapDrop"        "[ALL]"   "$(docker inspect "$CONTAINER_NAME" --format '{{.HostConfig.CapDrop}}')"
assert_eq "HostConfig.PidsLimit"      "128"     "$(docker inspect "$CONTAINER_NAME" --format '{{.HostConfig.PidsLimit}}')"
SECOPT="$(docker inspect "$CONTAINER_NAME" --format '{{.HostConfig.SecurityOpt}}')"
case "$SECOPT" in
  *no-new-privileges*) echo "    ok: HostConfig.SecurityOpt = $SECOPT" ;;
  *) fail "HostConfig.SecurityOpt does not mention no-new-privileges: '$SECOPT'" ;;
esac
assert_ne "HostConfig.Memory (must be limited)" "0" \
          "$(docker inspect "$CONTAINER_NAME" --format '{{.HostConfig.Memory}}')"

# ---------------------------------------------------------------------------
# 4. negative controls — every assertion above must be able to fail
# ---------------------------------------------------------------------------
echo "==> control: WITHOUT --read-only the same image must report a writable rootfs"
start_app --cap-drop ALL --security-opt no-new-privileges:true
assert_eq "root filesystem without --read-only" "writable" "$(probe rootfs)"

echo "==> control: WITHOUT --cap-drop ALL the bounding set must NOT be empty"
start_app --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m
CAPS="$(probe caps)"
case "$CAPS" in
  "CapBnd=0000000000000000"*) fail "bounding set is empty without --cap-drop ALL — the capability assertion proves nothing ($CAPS)" ;;
  *) echo "    ok: $CAPS" ;;
esac

echo "==> control: WITHOUT --security-opt no-new-privileges the kernel flag must be 0"
start_app --read-only --cap-drop ALL --tmpfs /tmp:rw,noexec,nosuid,size=64m
NNP="$(probe caps)"
case "$NNP" in
  *"NoNewPrivs=1") fail "no_new_privs is set without asking for it — that assertion proves nothing ($NNP)" ;;
  *) echo "    ok: $NNP" ;;
esac

echo "==> control: --user 0 overrides the image's USER (a Dockerfile USER is a default, not a control)"
start_app --user 0 --read-only --cap-drop ALL --tmpfs /tmp:rw,noexec,nosuid,size=64m
assert_eq "uid with --user 0" "uid=0 gid=0" "$(probe whoami)"

echo
echo "All docker baseline checks passed."
