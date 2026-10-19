package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	commlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	xserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// linkTestOptions holds the settings shared by every -test-links check.
type linkTestOptions struct {
	url           string
	timeout       time.Duration
	dns           []string
	queryStrategy string
	fragment      map[string]any
}

// linkTestResult is one line of -test-links output. Index is the link's line number in the
// input (0-based, counting skipped lines too); exactly one of MS and Error is set.
type linkTestResult struct {
	Index int    `json:"index"`
	MS    *int64 `json:"ms,omitempty"`
	Error string `json:"error,omitempty"`
}

// runLinkTests is the -test-links mode: it measures each link's real delay (an HTTP request to
// opts.url through that server, like v2rayNG's) with up to concurrency checks at a time, and
// writes one JSON line per link to stdout as soon as its check is done. Checks still running
// when ctx is canceled are dropped without output.
func runLinkTests(ctx context.Context, input io.Reader, concurrency int, opts linkTestOptions, debug bool) error {
	links, err := readLinkLines(input)
	if err != nil {
		return err
	}

	// stdout carries results here, but Xray logs to stdout by default: route its log to stderr
	// instead, and keep the per-check instances from replacing that (see testLink).
	severity := commlog.Severity_Error
	if debug {
		severity = commlog.Severity_Debug
	}
	commlog.RegisterHandler(&linkTestLogger{severity: severity, out: log.New(os.Stderr, "", log.LstdFlags)})

	var outMu sync.Mutex
	out := json.NewEncoder(os.Stdout)
	emit := func(r linkTestResult) {
		outMu.Lock()
		defer outMu.Unlock()
		out.Encode(r)
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
dispatch:
	for i, link := range links {
		if link == "" {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break dispatch
		}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			d, err := testLink(ctx, link, opts)
			if ctx.Err() != nil {
				return
			}
			r := linkTestResult{Index: i}
			if err != nil {
				r.Error = err.Error()
			} else {
				ms := d.Milliseconds()
				r.MS = &ms
			}
			emit(r)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		log.Println("Link test canceled")
	}
	return nil
}

// readLinkLines reads input line by line. Blank lines and "#" comments come back as "" so that
// indexes still match the input's line numbers.
func readLinkLines(input io.Reader) ([]string, error) {
	var links []string
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(links) == 0 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		if strings.HasPrefix(line, "#") {
			line = ""
		}
		links = append(links, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading links: %w", err)
	}
	return links, nil
}

// testLink starts a throwaway Xray instance with link as its only outbound and times one HTTP
// request to opts.url through it, from sending the request to receiving the response status.
func testLink(ctx context.Context, link string, opts linkTestOptions) (d time.Duration, err error) {
	// One malformed link must not take the whole batch down.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()

	cfg, err := parseProxyLink(link)
	if err != nil {
		return 0, fmt.Errorf("invalid link: %v", err)
	}
	// Same as -link mode: the SNI defaults to the link's own address, and -fragment applies to
	// connections that go straight to the server.
	if cfg.Params["sni"] == "" {
		cfg.Params["sni"] = cfg.Address
	}
	if !isLocalHost(cfg.Address) {
		cfg.Fragment = opts.fragment
	}
	// No mux: it would skew the first connection's time.
	jsonConfig, err := json.Marshal(map[string]any{
		"log":       map[string]any{"loglevel": "none", "access": "none"},
		"dns":       buildDNS(opts.dns, opts.queryStrategy),
		"outbounds": []any{buildOutbound(cfg, "proxy", 0)},
	})
	if err != nil {
		return 0, fmt.Errorf("invalid link: %v", err)
	}
	config, err := serial.LoadJSONConfig(bytes.NewReader(jsonConfig))
	if err != nil {
		return 0, fmt.Errorf("invalid link: %v", err)
	}
	config.App = withoutLogApp(config.App)
	server, err := core.New(config)
	if err != nil {
		return 0, fmt.Errorf("invalid link: %v", err)
	}
	if err := server.Start(); err != nil {
		return 0, errors.New(shortLinkError(err))
	}
	defer server.Close()

	// The outbound's own error (e.g. connection refused) only reaches the HTTP client as EOF,
	// so collect it on the side, the way Xray's observatory does for its probes.
	tracker := &outboundError{}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest, err := xnet.ParseDestination(network + ":" + addr)
				if err != nil {
					return nil, err
				}
				return core.Dial(session.TrackedConnectionError(ctx, tracker), server, dest)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	reqCtx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, opts.url, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if oerr := tracker.get(); oerr != nil {
			return 0, errors.New(shortLinkError(oerr))
		}
		if errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return 0, errors.New("timeout")
		}
		return 0, errors.New(shortLinkError(err))
	}
	d = time.Since(start)
	resp.Body.Close()
	return d, nil
}

// withoutLogApp drops Xray's log app from a built config. Each instance's log app would
// otherwise register itself as the process-wide log handler (writing to stdout), replacing the
// one runLinkTests installed, and silence all logging once that instance closes.
func withoutLogApp(apps []*xserial.TypedMessage) []*xserial.TypedMessage {
	kept := apps[:0]
	for _, app := range apps {
		if inst, err := app.GetInstance(); err == nil {
			if _, ok := inst.(*applog.Config); ok {
				continue
			}
		}
		kept = append(kept, app)
	}
	return kept
}

// outboundError receives the error of the check's outbound connection via
// session.TrackedConnectionError.
type outboundError struct {
	mu  sync.Mutex
	err error
}

func (o *outboundError) SubmitError(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.err = err
}

func (o *outboundError) get() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.err
}

// linkTestErrors maps substrings of common network errors to the short reasons -test-links
// reports, on Linux/Android and Windows alike.
var linkTestErrors = []struct{ needle, reason string }{
	{"connection refused", "connection refused"},
	{"actively refused", "connection refused"},
	{"connection reset", "connection reset"},
	{"forcibly closed", "connection reset"},
	{"no such host", "no such host"},
	{"network is unreachable", "network unreachable"},
	{"no route to host", "no route to host"},
	{"i/o timeout", "timeout"},
	{"deadline exceeded", "timeout"},
	{"no recent network activity", "timeout"},
	{"handshake did not complete in time", "timeout"},
}

// xrayCaller matches the "app/package: " prefix Xray puts on its errors.
var xrayCaller = regexp.MustCompile(`^[a-z0-9_]+(/[a-z0-9_]+)+: `)

// shortLinkError turns an error from a check into a short one-line reason: a known network
// error, the TLS error, or else the innermost one or two parts of Xray's "a > b > c" chain.
func shortLinkError(err error) string {
	// Drop the `Get "<url>":` prefix the HTTP client adds.
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	lower := strings.ToLower(s)
	for _, e := range linkTestErrors {
		if strings.Contains(lower, e.needle) {
			return e.reason
		}
	}
	if i := strings.Index(s, "tls: "); i >= 0 {
		return truncate(strings.SplitN(s[i:], " > ", 2)[0])
	}
	var parts []string
	for part := range strings.SplitSeq(s, " > ") {
		part = xrayCaller.ReplaceAllString(strings.TrimSpace(part), "")
		// common/retry lists the errors of its attempts in brackets.
		part = strings.TrimSuffix(strings.TrimPrefix(part, "["), "]")
		switch part {
		case "", "failed to process outbound traffic", "failed to find an available destination", "all retry attempts failed":
			continue
		}
		parts = append(parts, part)
	}
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	if len(parts) == 0 {
		return truncate(s)
	}
	return truncate(strings.Join(parts, ": "))
}

func truncate(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// linkTestLogger is Xray's process-wide log handler in -test-links mode: messages up to
// severity go to out (stderr), access logs nowhere.
type linkTestLogger struct {
	severity commlog.Severity
	out      *log.Logger
}

func (l *linkTestLogger) Handle(msg commlog.Message) {
	if m, ok := msg.(*commlog.GeneralMessage); ok && m.Severity <= l.severity {
		l.out.Println(m)
	}
}

// Severity lets Xray skip building messages that would be dropped anyway.
func (l *linkTestLogger) Severity() commlog.Severity {
	return l.severity
}
