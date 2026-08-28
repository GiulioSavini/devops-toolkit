# Docker & Container Security Baseline

Production-grade rules for securing Docker daemon, container images, and containerized workloads.

---

## 1. Docker Daemon Hardening (`/etc/docker/daemon.json`)

```json
{
  "icc": false,
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "5"
  }
}
```

---

## 2. Dockerfile Security Best Practices

```dockerfile
# 1. Use specific digest or minimal base image
FROM alpine:3.19 AS base

# 2. Run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# 3. Read-only filesystem friendly
WORKDIR /app
COPY --chown=appuser:appgroup app /app/

EXPOSE 8080
ENTRYPOINT ["/app/app"]
```

---

## 3. Runtime Security Parameters

Always run containers with dropped capabilities and read-only root filesystems when possible:

```bash
docker run -d \
  --name web-app \
  --read-only \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 80:80 \
  my-app:latest
```
