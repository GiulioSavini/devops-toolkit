// Minimal example workload used by tests/docker.sh and tests/kubernetes-e2e.sh
// to prove the hardened Dockerfile and the documented runtime flags actually
// work instead of merely being documented.
//
// The interesting part is that the assertions are made from INSIDE the
// container. `docker inspect` only shows what was requested (ReadonlyRootfs,
// CapDrop); these endpoints show what the kernel actually enforced, which is
// the only thing that matters — and it is the only way to check at all on a
// distroless image, which has no shell to exec into.
//
//	GET /healthz  -> "ok"
//	GET /whoami   -> "uid=65532 gid=65532"
//	GET /rootfs   -> "read-only" | "writable" | "permission-denied"
//	GET /tmpfs    -> "writable" | "read-only" | "permission-denied"
//	GET /caps     -> "CapBnd=0000000000000000 CapEff=0000000000000000 NoNewPrivs=1"
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// probeWrite reports what the kernel says when this process tries to create a
// file in dir, as one of three distinct answers.
//
// The three-way answer matters: EROFS ("read-only") is the mount being
// read-only, EACCES ("permission-denied") is only this uid lacking write
// permission on a writable filesystem. Collapsing them into one boolean is how
// a test ends up "passing" on an image where the rootfs was never read-only at
// all and the probe just happened to hit a directory the user cannot write.
func probeWrite(dir string) (string, error) {
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		switch {
		case errors.Is(err, syscall.EROFS):
			return "read-only", nil
		case errors.Is(err, os.ErrPermission):
			return "permission-denied", nil
		default:
			return "", err
		}
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return "writable", nil
}

// rootfsProbeDir picks a directory on the root filesystem that the runtime user
// owns, so that a writable rootfs really does answer "writable".
//
// In the distroless "nonroot" base image that is /home/nonroot (mode 0700,
// owned by 65532). Probing "/" instead would answer "permission-denied" for a
// non-root user even with a fully writable rootfs, which tests nothing.
func rootfsProbeDir() string {
	if d := os.Getenv("ROOTFS_PROBE_DIR"); d != "" {
		return d
	}
	for _, d := range []string{"/home/nonroot", os.Getenv("HOME")} {
		if d == "" {
			continue
		}
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	return "/"
}

// caps returns the process's bounding and effective capability bitmasks as the
// kernel reports them.
//
// CapBnd is the one worth asserting on. A process running as a non-root uid has
// an empty EFFECTIVE set no matter how the container was started, so CapEff
// alone cannot tell "--cap-drop ALL was honoured" apart from "this just happens
// to be a non-root process that could regain capabilities". The BOUNDING set is
// what --cap-drop ALL / capabilities.drop: ["ALL"] actually empties, and an
// empty bounding set is the guarantee that nothing in this container can ever
// acquire a capability — including a setuid binary someone adds later.
// NoNewPrivs is reported too: it is the kernel side of
// --security-opt no-new-privileges:true (and of
// allowPrivilegeEscalation: false in Kubernetes), and 1 here is the only proof
// that the flag took effect rather than being accepted and ignored.
func caps() (bnd string, eff string, nnp string, err error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "", "", "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "CapBnd:"):
			bnd = strings.TrimSpace(strings.TrimPrefix(line, "CapBnd:"))
		case strings.HasPrefix(line, "CapEff:"):
			eff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		case strings.HasPrefix(line, "NoNewPrivs:"):
			nnp = strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:"))
		}
	}
	if bnd == "" || eff == "" || nnp == "" {
		return "", "", "", errors.New("CapBnd/CapEff/NoNewPrivs not found in /proc/self/status")
	}
	return bnd, eff, nnp, nil
}

func plain(w http.ResponseWriter, format string, args ...any) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, format, args...)
}

func fail(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	plain(w, "error: %v\n", err)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		plain(w, "ok\n")
	})

	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		plain(w, "uid=%d gid=%d\n", os.Getuid(), os.Getgid())
	})

	// Probes the root filesystem, deliberately NOT a path that could be a
	// separate writable mount (/tmp, an emptyDir, a volume).
	mux.HandleFunc("/rootfs", func(w http.ResponseWriter, r *http.Request) {
		state, err := probeWrite(rootfsProbeDir())
		if err != nil {
			fail(w, err)
			return
		}
		plain(w, "%s\n", state)
	})

	// With a read-only rootfs, anything that needs scratch space needs an
	// explicit tmpfs (--tmpfs /tmp, or an emptyDir volume). This endpoint is
	// how the tests confirm that half of the pattern works too: a read-only
	// rootfs with no writable temp dir breaks most real applications.
	mux.HandleFunc("/tmpfs", func(w http.ResponseWriter, r *http.Request) {
		state, err := probeWrite(filepath.Clean(os.TempDir()))
		if err != nil {
			fail(w, err)
			return
		}
		plain(w, "%s\n", state)
	})

	mux.HandleFunc("/caps", func(w http.ResponseWriter, r *http.Request) {
		bnd, eff, nnp, err := caps()
		if err != nil {
			fail(w, err)
			return
		}
		plain(w, "CapBnd=%s CapEff=%s NoNewPrivs=%s\n", bnd, eff, nnp)
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		log.Printf("listening on :8080 as uid=%d gid=%d", os.Getuid(), os.Getgid())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}
}
