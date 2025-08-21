package dockerstartproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	httpcaddyfile "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

func init() {
	caddy.RegisterModule(Handler{})

	// Register the Caddyfile directive "docker_start_proxy"
	httpcaddyfile.RegisterHandlerDirective("docker_start_proxy", parseDockerStartProxy)
}

// parseDockerStartProxy lets the directive be used in Caddyfile.
// It simply reuses your UnmarshalCaddyfile implementation.
func parseDockerStartProxy(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return m, nil
}

// Handler is a Caddy HTTP middleware that ensures the derived Docker container
// is running and healthy before proxying the request to it.
type Handler struct {
	// Only configurable parameter kept minimal
	RedirectURL string `json:"redirect_url,omitempty"` // e.g. "https://storrito.localhost/signup"

	// Internal: Docker client
	docker *client.Client

	// Internal: HTTP client for health checks and hard-coded timings
	probeClient      *http.Client
	healthPath       string
	timeout          time.Duration
	pollInterval     time.Duration
	probeDialTimeout time.Duration
}

// ErrContainerNotFound is returned when the Docker container for a request is missing.
var ErrContainerNotFound = errors.New("container not found")

var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)

// Caddy module info.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.docker_start_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision initializes defaults and the Docker client.
func (h *Handler) Provision(ctx caddy.Context) error {
	// Hard-coded minimal defaults
	h.healthPath = "/health"
	h.timeout = 30 * time.Second
	h.pollInterval = 300 * time.Millisecond
	h.probeDialTimeout = 3 * time.Second

	cli, err := client.NewClientWithOpts(
		client.FromEnv, // honor DOCKER_HOST/DOCKER_TLS_VERIFY/DOCKER_CERT_PATH
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return fmt.Errorf("create docker client: %w", err)
	}
	h.docker = cli

	h.probeClient = &http.Client{
		Transport: &http.Transport{
			// Use default transport but tighten dial timeout.
			DialContext: (&net.Dialer{
				Timeout: h.probeDialTimeout,
			}).DialContext,
			// Keep defaults for TLS/HTTP2 off since we talk to upstream via HTTP in-cluster.
			DisableKeepAlives: false,
		},
		Timeout: 5 * time.Second, // overall per-request probe timeout
	}

	return nil
}

// UnmarshalCaddyfile supports a minimal Caddyfile block:
//
//	docker_start_proxy {
//	  redirect_url https://example.com/fallback
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "redirect_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.RedirectURL = d.Val()

			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// ServeHTTP implements the middleware logic.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	host := r.Host
	if host == "" {
		return caddyhttp.Error(http.StatusBadRequest, errors.New("missing Host header"))
	}

	// Strip port if present (Host may be "example.com:443")
	if colon := strings.IndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}

	leftmost := leftmostLabel(host)
	if leftmost == "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("cannot derive subdomain from host %q", r.Host))
	}

	containerName := "org-" + leftmost
	upstreamHost := containerName
	upstreamURL := fmt.Sprintf("http://%s:8080", upstreamHost)

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Ensure container is running (start if needed).
	if err := h.ensureRunning(ctx, containerName); err != nil {
		if errors.Is(err, ErrContainerNotFound) && h.RedirectURL != "" {
			http.Redirect(w, r, h.RedirectURL, http.StatusTemporaryRedirect)
			return nil
		}
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("container %s not ready: %w", containerName, err))
	}

	// Wait for health readiness.
	if err := h.waitHealthy(ctx, upstreamURL+h.healthPath); err != nil {
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("container %s not healthy: %w", containerName, err))
	}

	// Reverse proxy to upstream.
	target, _ := url.Parse(upstreamURL)
	rp := httputil.NewSingleHostReverseProxy(target)

	// Preserve original Host header for app logic while still routing to upstream.
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		// Keep incoming Host header (so app sees foo.example.com)
		req.Host = r.Host
		// You may want to forward X-Forwarded-*; Caddy usually sets these,
		// but since we bypass caddyhttp/reverseproxy, set the essentials:
		req.Header.Set("X-Forwarded-Host", r.Host)
		req.Header.Set("X-Forwarded-Proto", schemeFromRequest(r))
		req.Header.Set("X-Forwarded-For", clientIPFromRequest(r))
	}

	rp.ServeHTTP(w, r)
	return nil
}

func (h Handler) ensureRunning(ctx context.Context, name string) error {
	// Find container by name (exact match)
	args := filters.NewArgs()
	args.Add("name", "^"+name+"$") // Docker regex anchors
	containers, err := h.docker.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: args,
	})
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	if len(containers) == 0 {
		return fmt.Errorf("%w: %q", ErrContainerNotFound, name)
	}

	// If not running, start it.
	c := containers[0]
	if c.State != "running" {
		if err := h.docker.ContainerStart(ctx, c.ID, container.StartOptions{}); err != nil {
			return fmt.Errorf("start container %q: %w", name, err)
		}
	}
	return nil
}

func (h Handler) waitHealthy(ctx context.Context, healthURL string) error {
	t := time.NewTicker(h.pollInterval)
	defer t.Stop()

	for {
		// Attempt probe
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		resp, err := h.probeClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			if err != nil {
				return fmt.Errorf("health check timed out: last error: %w", err)
			}
			return fmt.Errorf("health check timed out with status %v", respStatusMaybe(resp))
		case <-t.C:
			// keep polling
		}
	}
}

func leftmostLabel(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func schemeFromRequest(r *http.Request) string {
	if r.Header.Get("X-Forwarded-Proto") != "" {
		return r.Header.Get("X-Forwarded-Proto")
	}
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	// Caddy sits in front; default to https if original was TLS-terminated at Caddy
	if strings.EqualFold(os.Getenv("CADDY_TERMINATES_TLS"), "true") {
		return "https"
	}
	return "http"
}

func clientIPFromRequest(r *http.Request) string {
	// Trust prior XFF if already present; append current remote addr else.
	xff := r.Header.Get("X-Forwarded-For")
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if xff == "" {
		return host
	}
	return xff + ", " + host
}

func respStatusMaybe(resp *http.Response) any {
	if resp == nil {
		return "no response"
	}
	return resp.Status
}
