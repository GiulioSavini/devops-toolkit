# Docker and Container Security

A baseline for building and running containers on a Docker host: image build,
daemon configuration, runtime flags, registry trust and host-level boundaries.
Everything here ships as a file under
[`baselines/docker/`](../baselines/docker/) and is validated by
[`tests/docker.sh`](../tests/docker.sh), which builds the image, runs it with
the documented flags, and then asks the container what the kernel actually gave
it.

| | |
|---|---|
| Applies to | Docker Engine 25.0+ (tested on 29.8), containerd 1.7+, cgroup v2 hosts, Linux kernel 5.15+ |
| Baseline files | [`baselines/docker/Dockerfile`](../baselines/docker/Dockerfile), [`baselines/docker/daemon.json`](../baselines/docker/daemon.json), [`baselines/docker/example-app/`](../baselines/docker/example-app/) |
| Validated by | [`tests/docker.sh`](../tests/docker.sh) |
| Lockout risk | **Low on the container side, medium on the daemon side.** `icc: false` and `userland-proxy: false` change host networking behaviour and need a daemon restart, which stops every container that is not covered by `live-restore` |
| Last reviewed | 2026-09 |

## Threat model

What this baseline is for:

- **Container to host escape.** A process that gets code execution inside a
  container and tries to reach the host: capabilities it should not have,
  setuid binaries, `/proc` and `/sys` writes, a writable Docker socket.
- **Lateral movement between containers.** Default bridge networking lets every
  container on it talk to every other one, so one compromised sidecar reaches
  the database container directly.
- **Image supply chain.** A tag that is re-pushed to point at different
  content, a base image with known CVEs, a build that pulls unpinned
  dependencies.
- **Blast radius of a compromised workload.** A container that can exhaust the
  host's memory, PIDs or disk is a denial of service on every other workload on
  that host.
- **Secrets in images.** A credential in a build argument or an intermediate
  layer stays in the image after the final layer deletes it.

What it is not for:

- **Untrusted, multi-tenant workloads.** Containers share the host kernel. A
  kernel LPE is a full escape regardless of anything in this guide. If the
  workload is genuinely untrusted, use a VM boundary: Kata Containers,
  Firecracker, or a separate host.
- **Root inside the container being harmless.** With user namespaces off —
  which is the default — uid 0 in the container is uid 0 on the host, and only
  capability and seccomp filtering stands between them.
- **Anyone with access to the Docker socket.** `docker run -v /:/host` is a
  root shell on the host, by design. Socket access is root access; treat the
  `docker` group as such.
- **Orchestrated workloads.** On Kubernetes the enforcement point is admission
  control and the pod spec, not `docker run` flags. See
  [Kubernetes hardening](kubernetes-hardening.md).

## Image build

[`baselines/docker/Dockerfile`](../baselines/docker/Dockerfile) is a two-stage
build: a full `golang` toolchain image that is never shipped, and a
`gcr.io/distroless/static-debian12:nonroot` final stage that contains the
binary and nothing else.

Four decisions in that file carry most of the value.

**Both base images are pinned by digest, not tag.** A tag is a mutable pointer.
`golang:1.27-bookworm` today and the same tag next month can be different
images, including a compromised one, and nothing in the build output says so.
A digest cannot change. Resolve one with either of:

```bash
docker pull golang:1.27-bookworm
docker image inspect --format '{{index .RepoDigests 0}}' golang:1.27-bookworm
crane digest golang:1.27-bookworm      # no daemon needed
```

Pinning is not "set once and forget": it converts silent drift into an explicit
change. Let Dependabot or Renovate raise the bump as a reviewable pull request,
so you still get the security patches you want — as a diff someone approved.
[`.github/dependabot.yml`](../.github/dependabot.yml) in this repository does
that for the Actions used by CI.

**The final stage is distroless.** No shell, no package manager, no libc. An
attacker with code execution has no `sh -c` to pivot with, no `apt` to install
tooling, no dynamic loader to abuse. This is why the build sets
`CGO_ENABLED=0`: the binary must be fully static to run with no libc present.
`-trimpath` and `-ldflags="-s -w"` drop local filesystem paths and debug
symbols, which makes the image smaller and leaks less if the binary is ever
extracted from a leaked image.

The cost is real and you should expect it: **you cannot `docker exec` into this
image**, because there is nothing to exec. Debugging happens through the
application's own endpoints, through logs, or with `docker run
--pid=container:<id>` from a debug image. `tests/docker.sh` hit exactly this,
which is why the example app exposes its own introspection endpoints instead of
the test shelling in.

**`USER 65532:65532` is stated even though the base image already sets it.**
It is deliberately redundant. Having it in the Dockerfile means a base-image
change that reverts to root shows up in the diff, and gives
`docker inspect --format '{{.Config.User}}'` — or an admission policy that
reads the same field — something to check.

**`COPY --chown=65532:65532`.** Under `--read-only` there is no init step that
can fix ownership at startup. If the binary is owned by root and not
world-readable, the container fails to start with a permission error that looks
nothing like its cause.

**There is no `HEALTHCHECK`.** The usual `CMD curl -f
http://localhost:8080/healthz` cannot run in an image with no shell and no
curl. Either the application self-probes through its own binary as a
subcommand, or the orchestrator probes it — which is what the readiness and
liveness probes in
[`baselines/kubernetes/hardened-deployment.yaml`](../baselines/kubernetes/hardened-deployment.yaml)
do.

### What a Dockerfile cannot do

`USER` in a Dockerfile is a **default, not a control**. `docker run --user 0`
overrides it, and so does a Kubernetes pod spec with a different
`runAsUser`. `tests/docker.sh` asserts this explicitly, because the difference
between a default and a control is the difference between a hardening measure
and a hardening comment:

```bash
docker run --user 0 ... "$IMAGE"    # uid=0 gid=0, despite USER 65532
```

The enforcement point is the runtime — the flags below, or
`runAsNonRoot: true` plus Pod Security Admission on Kubernetes.

## Daemon configuration

[`baselines/docker/daemon.json`](../baselines/docker/daemon.json) goes in
`/etc/docker/daemon.json`.

| Key | Value | Why |
|---|---|---|
| `icc` | `false` | Turns off inter-container communication on the default bridge. Containers that must talk get an explicit user-defined network. Without this, one compromised container reaches every other container on the host over the network |
| `no-new-privileges` | `true` | Daemon-wide default for the `no_new_privs` bit: a process in the container can never gain privileges through a setuid binary. Per-container `--security-opt` still applies on top |
| `live-restore` | `true` | Containers keep running across a daemon restart. Without it, every `systemctl restart docker` — including the one that applies this file — is an outage |
| `userland-proxy` | `false` | Published ports are handled by iptables DNAT instead of a `docker-proxy` userland process per port. One less process per published port, and the container sees the real client address |
| `default-cgroupns-mode` | `private` | Each container gets its own cgroup namespace, so it cannot read or modify the host's cgroup hierarchy through `/sys/fs/cgroup` |
| `log-driver` + `log-opts` | `json-file`, 50m × 5 | Caps log growth. The default `json-file` driver has **no** size limit, and a container that logs in a loop fills `/var/lib/docker` and takes the host down |
| `default-ulimits` `nofile` | 1024 / 4096 | A file-descriptor ceiling that applies to containers that did not ask for one |

Validate before restarting the daemon:

```bash
dockerd --validate --config-file=/etc/docker/daemon.json
```

That parses the file with the daemon's own config loader and exits without
starting anything, so it catches an unknown key or a wrong type — the two
mistakes that otherwise surface as a daemon that refuses to start after a
reboot, at the worst possible time. `tests/docker.sh` runs this check and then
runs it again against `{"icc": "not-a-bool"}`, which must be rejected; without
that control, a validator that accepts everything would make the check
meaningless.

### What is deliberately not in this file

- **`userns-remap`.** User namespace remapping is the single strongest
  container isolation feature Docker has, and it breaks things: volumes owned
  by the pre-remap uid become unreadable, `--net=host` and `--pid=host`
  containers cannot use it, and some images assume real uid 0. Enable it
  per-host after testing, not as a blanket baseline.
- **A custom seccomp profile.** Docker's default seccomp profile already
  blocks around 40 syscalls, including `kexec_load`, `bpf` and
  `mount`. Replacing it with a hand-written profile is how people end up
  running `--security-opt seccomp=unconfined` when something breaks. Narrow the
  default with a generated profile per workload if you have the tooling to
  maintain it; do not hand-edit one into a baseline.
- **`"iptables": false`.** Suggested by some guides. It stops Docker managing
  its own NAT rules, which breaks published ports unless you have replaced the
  whole rule set yourself. See the nftables section of
  [Linux hardening](linux-hardening.md) for how to run a host firewall that
  coexists with Docker's chains.

## Runtime flags

These are the flags [`tests/docker.sh`](../tests/docker.sh) runs the example
image with, and then verifies from inside the container:

```bash
docker run -d --name web-app \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1.0 \
  -p 127.0.0.1:8080:8080 \
  myapp:sha256-pinned-digest
```

| Flag | Effect |
|---|---|
| `--read-only` | Root filesystem mounted read-only. An attacker cannot drop a binary, modify the application, or persist across a restart |
| `--cap-drop ALL` | Empties the capability **bounding** set. Add back only what the process genuinely needs — `--cap-add NET_BIND_SERVICE` for a port below 1024, and nothing else. Better still, listen above 1024 and publish the low port on the host |
| `--security-opt no-new-privileges:true` | Sets the kernel `no_new_privs` bit, so no setuid binary in the image can raise privileges |
| `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | The writable scratch space a read-only container usually still needs, with a size cap so it cannot eat host memory, and `noexec` so it is not a staging area for a dropped payload |
| `--pids-limit` | Caps processes. A fork bomb in one container stops being a host-wide outage |
| `--memory`, `--cpus` | Resource ceilings. Without `--memory`, a container can drive the host into the OOM killer, which then picks a victim that may not be the offender |
| `-p 127.0.0.1:8080:8080` | Publishes to loopback only. `-p 8080:8080` binds `0.0.0.0` and — because Docker's DNAT rules are evaluated before the `INPUT` chain — is reachable from the network **even if your host firewall drops port 8080** |

Never combine these with the flags that undo them: `--privileged`,
`--cap-add SYS_ADMIN`, `--pid=host`, `--net=host`, `--security-opt
seccomp=unconfined`, `--security-opt apparmor=unconfined`, or a bind mount of
`/var/run/docker.sock`. Each of those is, on its own, a documented path to host
root.

### Inspecting what was requested is not verifying what was applied

`docker inspect` reports what you **asked for**. The kernel decides what you
**got**. `tests/docker.sh` checks both, and the distinction is why the example
app exposes `/whoami`, `/rootfs`, `/tmpfs` and `/caps`: on a distroless image
there is no shell to exec into, so asking the process itself is the only way to
ask at all.

Two traps that came out of writing those assertions:

- **Assert on the capability bounding set, not the effective set.** A non-root
  process has an empty *effective* set even with no `--cap-drop` at all, so an
  assertion on `CapEff` passes on a completely unhardened container. `CapBnd=0`
  is the statement that matters: nothing in this container can ever acquire a
  capability.
- **`EROFS` and `EACCES` are different answers.** A write that fails with
  "permission denied" means this uid lacks write permission on a *writable*
  filesystem; only `EROFS` means the mount is read-only. Collapsing them into
  one boolean is how a test passes on an image whose rootfs was never read-only
  and the probe just happened to hit a directory the user cannot write.

## Registry and image trust

```bash
# Scan before promoting, and fail the build on fixable findings only —
# an unfixable CVE in the base image cannot be actioned by this pipeline.
trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed myapp:tag

# Generate an SBOM and keep it as a build artifact: it is what you grep
# when the next log4shell lands and someone asks "are we affected".
syft myapp:tag -o spdx-json > sbom.spdx.json

# Sign keylessly in CI, and verify at admission time.
cosign sign --yes myapp@sha256:<digest>
cosign verify myapp@sha256:<digest> \
  --certificate-identity-regexp '^https://github\.com/<org>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A signature verified only in the pipeline that produced it proves nothing —
that pipeline is the thing you are trying to protect. Verification has to
happen at the point of use: an admission controller on Kubernetes, or a
pre-deploy gate that the deploying identity cannot bypass. See
[CI/CD security](cicd-security.md) for the pipeline side and
[Kubernetes hardening](kubernetes-hardening.md) for admission.

Deploy by digest, not tag. `myapp:v1.2.3` can be re-pushed;
`myapp@sha256:...` cannot.

## Host-level boundaries

The container flags above do nothing about the daemon itself.

- **`/var/run/docker.sock` is a root credential.** Anything that can write to
  it can start a privileged container that mounts `/`. Never bind-mount it into
  a container that runs untrusted code or third-party images. If a workload
  needs to build images, use a rootless builder (`buildkitd` in rootless mode,
  or Buildah) rather than handing over the socket.
- **The `docker` group is the root group.** Adding a user to it is granting
  passwordless root without `sudo` logging it. Audit its membership the way you
  audit `sudoers`.
- **Run the daemon rootless where the workload allows it.** Rootless Docker
  moves the whole daemon into a user namespace, so a container escape lands as
  an unprivileged user. It cannot bind ports below 1024 without extra setup and
  has no support for some networking modes; that is the trade.
- **Keep the storage driver on `overlay2`.** It is the only driver that gets
  security attention.
- **Prune deliberately, not automatically.** `docker system prune -af` deletes
  images an incident responder may need. Prune dangling layers on a schedule;
  keep the digests you deployed.

## Rollout

1. Build and push the hardened image. Deploy it **without** the new runtime
   flags first, so an application failure is distinguishable from a flag
   problem.
2. Add `--read-only` plus the `--tmpfs` mounts. This is the flag that most
   often breaks an application: find every path it writes with
   `strace -f -e trace=openat,creat` or by reading its config, and mount each
   one as an explicit tmpfs or volume.
3. Add `--cap-drop ALL`. If the process fails to bind its port, do not add
   `--cap-add NET_BIND_SERVICE` reflexively: move the listener above 1024 and
   publish the low port on the host instead.
4. Add `--security-opt no-new-privileges:true`, then the resource limits.
   Set `--memory` from observed peak usage plus headroom, not from a guess —
   too low and the container is OOM-killed under load, which looks like a crash
   loop.
5. Apply `daemon.json` last, and on one host first. Validate with
   `dockerd --validate`, confirm `live-restore` is already in effect from a
   previous restart, then `systemctl restart docker`. Expect `icc: false` to
   break any container pair that was relying on the default bridge; that is the
   finding, not a regression.

## Verification

```bash
# Daemon: the effective configuration, not the file
docker info --format '{{json .SecurityOptions}}'
# expect seccomp, apparmor (or selinux), and no "name=userns" missing surprise

# Every running container: who is root, who is privileged, who has the socket
docker ps -q | xargs -r docker inspect \
  --format '{{.Name}} user={{.Config.User}} priv={{.HostConfig.Privileged}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapAdd}}'

# Anything with the daemon socket mounted in — treat each as host root
docker ps -q | xargs -r docker inspect \
  --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' | grep docker.sock

# From inside a container, what the kernel actually applied
grep -E '^(CapBnd|CapEff|NoNewPrivs)' /proc/1/status
# expect CapBnd=0000000000000000 and NoNewPrivs=1

# Host-side CIS checks, including the daemon.json keys above
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security
```

`docker-bench-security` needs broad host access to do its job, which is exactly
the access this guide says not to grant: run it as an audit task and remove the
container afterwards, not as a sidecar.

## Rollback

| Change | Undo |
|---|---|
| Runtime flags | Re-run the container without them. No host state changes |
| `--read-only` breaking writes | Add the specific path as a `--tmpfs` or named volume before removing `--read-only` wholesale |
| `daemon.json` | Restore the previous file, `dockerd --validate`, `systemctl restart docker`. With `live-restore: true` already active, running containers survive |
| `icc: false` | Remove the key, or better, put the container pair on a shared user-defined network and keep the key |
| `userland-proxy: false` | Remove the key and restart; published ports move back to a `docker-proxy` process each |
| Digest pin | Bump the digest, never loosen back to a bare tag |

## Common failure modes

- **`--read-only` breaks the application weeks later**, when it first tries to
  write a cache or a lock file on a code path that only runs under load.
- **`nofile` too low.** The 1024/4096 default here is conservative; a busy
  proxy or a JVM needs more, and the failure is `too many open files` under
  load, not at startup.
- **`-p 8080:8080` exposed to the internet** on a host whose firewall drops
  8080, because Docker's DNAT happens before `INPUT`. Publish to `127.0.0.1`
  and put a reverse proxy in front.
- **`icc: false` applied to a host whose containers used the default bridge to
  reach each other.** They stop resolving and connecting, with no error that
  points at the daemon config.
- **A restart without `live-restore`** taking down every container on the host,
  during what was supposed to be a config change.
- **Log growth** filling `/var/lib/docker` on a host that set a log driver but
  no `max-size`.
- **Secrets passed as `--build-arg`** and then visible in
  `docker history`. Use BuildKit secret mounts
  (`RUN --mount=type=secret,id=token`), which never land in a layer.
- **`USER` in the Dockerfile treated as a security control**, and then a
  deployment manifest that quietly runs the same image as uid 0.
- **A `latest` tag in production**, so nobody can say what is actually running,
  and a rollback pulls the same broken image.

## Control mapping

Section to control families. Benchmark section numbers are deliberately not
cited: verify them against the exact benchmark version you are audited on.

| This guide | CIS Benchmark | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Annex A | NIS2 Art. 21(2) |
|---|---|---|---|---|
| Image build, digest pinning | CIS Docker Benchmark | CM-2, CM-6, SA-12 | A.8.9, A.8.30 | (d), (e) |
| Daemon configuration | same | CM-6, CM-7, SC-7 | A.8.9, A.8.20 | (e) |
| Runtime flags, capabilities | same | AC-6, CM-7, SC-2 | A.8.2, A.8.19 | (i) |
| Resource limits | same | SC-5, SC-6 | A.8.6 | (c) |
| Registry trust, signing, SBOM | same | SA-10, SA-11, SI-7 | A.8.28, A.8.30, A.5.21 | (d) |
| Vulnerability scanning | same | RA-5, SI-2 | A.8.8 | (e) |
| Socket and group access | same | AC-2, AC-6, AU-2 | A.5.15, A.8.2 | (i) |
| Logging and log rotation | same | AU-4, AU-11 | A.8.15 | (b) |

## References

- [Docker Engine security](https://docs.docker.com/engine/security/) and
  [`dockerd` reference](https://docs.docker.com/reference/cli/dockerd/) for
  every `daemon.json` key
- [`docker run` reference](https://docs.docker.com/reference/cli/docker/container/run/)
  for the runtime flags and their exact semantics
- [Docker rootless mode](https://docs.docker.com/engine/security/rootless/)
- [Distroless images](https://github.com/GoogleContainerTools/distroless) and
  the `:nonroot` variants
- [BuildKit secret mounts](https://docs.docker.com/build/building/secrets/)
- [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)
  and [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [Sigstore / cosign](https://docs.sigstore.dev/) for keyless signing and
  verification
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) — the
  authoritative section numbers for your audited version
- [Kubernetes hardening](kubernetes-hardening.md) for the orchestrated
  enforcement points, and [Linux hardening](linux-hardening.md) for the host
  the daemon runs on
