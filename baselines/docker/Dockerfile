# Hardened multi-stage build, referenced by guides/docker-security.md.
# Validated end-to-end by tests/docker.sh: built, run with the flags from
# that guide's "Runtime security parameters" section, and probed as non-root
# with a read-only root filesystem.
#
# Base images are pinned by digest, not just tag: a tag can be re-pushed to
# point at a different (and possibly compromised) image; a digest cannot.
# Both digests below were the current contents of their tag on 2026-09-28.
# Re-resolve them regularly (`docker pull <image>:<tag>` then
# `docker image inspect --format '{{index .RepoDigests 0}}' <image>:<tag>`, or
# `crane digest <image>:<tag>` without a daemon) and let Dependabot/Renovate
# raise the bump as a reviewable PR — pinning is not "set once and forget",
# it converts silent drift into an explicit change, including the security
# patches you do want.

# Builder stage: never shipped, so it can be a full toolchain image.
FROM golang:1.27-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS builder

WORKDIR /src
COPY example-app/go.mod ./
COPY example-app/main.go ./

# CGO disabled: the binary must be fully static to run on a scratch/distroless
# base with no libc. -trimpath and -ldflags="-s -w" drop local filesystem
# paths and debug symbols from the binary (smaller image, less information
# disclosure if the binary is ever extracted from a leaked image).
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/app .

# Final stage: distroless "static" + "nonroot" variant.
# - No shell, no package manager, no libc: nothing for an attacker who gets
#   code execution to pivot with (no `sh -c`, no `apt`, no dynamic loader to
#   abuse).
# - The "nonroot" tag already runs as uid/gid 65532 (see the image's
#   /etc/passwd), so there is no USER instruction to add here — unlike a
#   distro-based image, this base cannot silently fall back to root because
#   there is no root shell to fall back into.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# COPY --chown after the base image already sets USER: ownership must match
# the nonroot UID/GID or the binary is unreadable at runtime under
# --read-only (there is no init process available to chmod it on start).
COPY --from=builder --chown=65532:65532 /out/app /app/app

# Redundant with the :nonroot base image, and kept on purpose: it states the
# runtime identity in this file, so a base-image change that reverts to root
# shows up in the diff, and `docker inspect --format '{{.Config.User}}'` (or an
# admission policy that reads it) has something to check.
USER 65532:65532

# No HEALTHCHECK: this image has no shell and no curl, so the usual
# `CMD curl -f http://localhost:8080/healthz` cannot run. Either the app
# self-probes through its own binary (`ENTRYPOINT`-compatible subcommand), or
# the orchestrator probes it — which is what the readiness/liveness probes in
# baselines/kubernetes/hardened-deployment.yaml do.
EXPOSE 8080
ENTRYPOINT ["/app/app"]
