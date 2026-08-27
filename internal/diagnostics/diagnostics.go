// Package diagnostics contains safe, operator-facing deployment checks.
//
// Reports intentionally contain only effective listener/origin metadata and
// bounded remediation text. They must never include credentials, raw proxy
// headers, or provider URLs.
package diagnostics

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/crypt0rr/tailstate/internal/boot"
)

// Severity is the impact level of a diagnostic finding.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Finding is a safe, actionable deployment observation.
type Finding struct {
	Code        string   `json:"code"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	Remediation string   `json:"remediation"`
}

// RequestInfo contains sanitized information about the request's effective
// public origin. It deliberately omits raw Origin, Referer, and forwarded
// header values.
type RequestInfo struct {
	Origin           string `json:"origin,omitempty"`
	Scheme           string `json:"scheme,omitempty"`
	ForwardedProto   string `json:"forwarded_proto,omitempty"`
	PeerTrustedProxy bool   `json:"peer_trusted_proxy"`
	ForwardedHeaders bool   `json:"forwarded_headers"`
}

// Runtime describes the non-secret state needed for operator diagnostics.
type Runtime struct {
	Configured          bool
	BaselineReady       bool
	BaselineDegraded    bool
	BaselineReason      string
	Destinations        int
	EnabledDestinations int
	Storage             StorageRuntime
}

// StorageRuntime is a safe, low-cardinality view of the persistence
// guardrails. It contains sizes and counters only; provider payloads and
// destination credentials are intentionally absent.
type StorageRuntime struct {
	SnapshotLimitBytes      int64
	EventValueLimitBytes    int64
	HistoryPageLimitBytes   int64
	RejectLimitBytes        int64
	DatabaseLimitBytes      int64
	DatabaseBytes           int64
	StoragePressure         float64
	SnapshotTruncations     uint64
	EventValueTruncations   uint64
	HistoryPageTruncations  uint64
	OversizedWritesRejected uint64
}

// Report is the complete safe deployment report.
type Report struct {
	State             string         `json:"state"`
	Listener          string         `json:"listener"`
	CookieSecure      bool           `json:"cookie_secure"`
	TrustedProxyCount int            `json:"trusted_proxy_count"`
	Request           RequestInfo    `json:"request"`
	Findings          []Finding      `json:"findings"`
	Storage           StorageRuntime `json:"storage"`
}

// Build evaluates static configuration, optional runtime state, and (when
// supplied) the current HTTP request. The request is used only to derive
// sanitized origin metadata and proxy findings.
func Build(config boot.Config, runtime Runtime, request *http.Request) Report {
	report := Report{
		State:             "ok",
		Listener:          config.ListenAddr,
		CookieSecure:      config.CookieSecure,
		TrustedProxyCount: len(config.TrustedProxies),
		Findings:          make([]Finding, 0, 8),
		Storage:           runtime.Storage,
	}

	add := func(f Finding) {
		report.Findings = append(report.Findings, f)
		if f.Severity == SeverityError {
			report.State = "error"
		} else if f.Severity == SeverityWarning && report.State == "ok" {
			report.State = "warning"
		}
	}

	if config.InsecureHTTPListener() {
		add(Finding{
			Code:     "plaintext_public_listener",
			Severity: SeverityWarning,
			Summary:  "The authenticated UI is exposed on a non-loopback plaintext listener.",
			Remediation: "Bind TAILSTATE_LISTEN_ADDR to loopback, or put TailState behind an HTTPS proxy and enable " +
				"TAILSTATE_COOKIE_SECURE=true.",
		})
	}
	if config.CookieSecure && len(config.TrustedProxies) == 0 {
		add(Finding{
			Code:        "secure_cookie_without_proxy",
			Severity:    SeverityError,
			Summary:     "Secure cookies are enabled but no trusted HTTPS proxy is configured.",
			Remediation: "Set TAILSTATE_TRUSTED_PROXIES to the proxy's actual source address, or disable secure cookies only for a local HTTP deployment.",
		})
	}
	if _, ok := os.LookupEnv("TAILSTATE_BIND_ADDRESS"); ok {
		add(Finding{
			Code:        "compose_publish_address",
			Severity:    SeverityInfo,
			Summary:     "TAILSTATE_BIND_ADDRESS controls the Compose host port, not the process listener.",
			Remediation: "Use TAILSTATE_LISTEN_ADDR to change the address served by the TailState process.",
		})
	}

	if !runtime.Configured {
		add(Finding{
			Code:        "installation_incomplete",
			Severity:    SeverityInfo,
			Summary:     "The installation has not been claimed and monitoring is not configured.",
			Remediation: "Open /setup locally or through the configured HTTPS proxy and complete the initial setup.",
		})
	} else {
		if !runtime.BaselineReady {
			add(Finding{
				Code:        "baseline_pending",
				Severity:    SeverityInfo,
				Summary:     "Monitoring is configured but no usable baseline is ready yet.",
				Remediation: "Keep the service running and check /readyz for bounded collector progress details.",
			})
		}
		if runtime.BaselineDegraded {
			add(Finding{
				Code:        "baseline_degraded",
				Severity:    SeverityWarning,
				Summary:     "Monitoring has a baseline but one or more collectors are degraded.",
				Remediation: "Review the authenticated Status page and collector health; upstream error details remain out of unauthenticated responses.",
			})
		}
		if runtime.Destinations > 0 && runtime.EnabledDestinations == 0 {
			add(Finding{
				Code:        "notifications_paused",
				Severity:    SeverityWarning,
				Summary:     "All notification destinations are disabled, so notifications are paused.",
				Remediation: "Enable at least one destination in Settings; monitoring and history continue while delivery is paused.",
			})
		}
	}
	if runtime.Storage.DatabaseLimitBytes > 0 && runtime.Storage.StoragePressure >= 0.9 {
		severity := SeverityWarning
		summary := "TailState storage is approaching its configured database budget."
		remediation := "Review retention and history exports, then increase the database budget or move the data directory before writes are rejected."
		if runtime.Storage.StoragePressure >= 1 {
			severity = SeverityError
			summary = "TailState storage is at or above its configured database budget."
			remediation = "Increase the database budget or reclaim retained history before collecting more data."
		}
		add(Finding{Code: "storage_pressure", Severity: severity, Summary: summary, Remediation: remediation})
	}

	if request != nil {
		report.Request = requestInfo(config, request)
		if report.Request.ForwardedHeaders && !report.Request.PeerTrustedProxy {
			add(Finding{
				Code:        "untrusted_forwarded_headers",
				Severity:    SeverityWarning,
				Summary:     "The request supplied forwarded headers from a peer that is not trusted.",
				Remediation: "Trust only the reverse proxy's actual source address in TAILSTATE_TRUSTED_PROXIES; TailState will ignore forwarded headers from other peers.",
			})
		}
		if config.CookieSecure && report.Request.Scheme != "https" {
			add(Finding{
				Code:        "https_forward_missing",
				Severity:    SeverityError,
				Summary:     "The current request does not look HTTPS even though secure cookies are enabled.",
				Remediation: "Preserve the public Host and send X-Forwarded-Proto: https from a trusted proxy, or access the local HTTP listener directly during setup.",
			})
		}
	}

	return report
}

// HasErrors reports whether the report contains a blocking finding.
func (r Report) HasErrors() bool {
	return r.State == "error"
}

func requestInfo(config boot.Config, request *http.Request) RequestInfo {
	info := RequestInfo{}
	info.PeerTrustedProxy = trustedProxy(config, remoteIP(request))
	forwardedProto := firstForwardedValue(request.Header.Get("X-Forwarded-Proto"))
	info.ForwardedProto = forwardedProto
	info.ForwardedHeaders = strings.TrimSpace(request.Header.Get("X-Forwarded-Proto")) != "" || strings.TrimSpace(request.Header.Get("X-Forwarded-For")) != ""

	info.Scheme = "http"
	if request.TLS != nil || (info.PeerTrustedProxy && strings.EqualFold(forwardedProto, "https")) {
		info.Scheme = "https"
	}
	if host := sanitizedHost(request.Host); host != "" {
		info.Origin = (&url.URL{Scheme: info.Scheme, Host: host}).String()
	}
	return info
}

func remoteIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(request.RemoteAddr)
}

func trustedProxy(config boot.Config, raw string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	for _, prefix := range config.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func firstForwardedValue(raw string) string {
	value := strings.TrimSpace(strings.Split(raw, ",")[0])
	if value == "http" || value == "https" {
		return value
	}
	return ""
}

func sanitizedHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse("//" + raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		return hostname
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return ""
	}
	return net.JoinHostPort(hostname, port)
}
