package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	SourceURL                  string   `json:"source_url"`
	ScanIntervalSeconds        int      `json:"scan_interval_seconds"`
	OutputFile                 string   `json:"output_file"`
	DetailsFile                string   `json:"details_file"`
	StateFile                  string   `json:"state_file"`
	LogFile                    string   `json:"log_file"`
	MaxWorkers                 int      `json:"max_workers"`
	ConnectTimeoutSeconds      int      `json:"connect_timeout_seconds"`
	RequestTimeoutSeconds      int      `json:"request_timeout_seconds"`
	VerifyTLS                  bool     `json:"verify_tls"`
	ProbeHTTP                  bool     `json:"probe_http"`
	ProbeHTTPS                 bool     `json:"probe_https"`
	RequireDomainResolvesToIP  bool     `json:"require_domain_resolves_to_ip"`
	ForceProbeIP               bool     `json:"force_probe_ip"`
	FollowCrossHostRedirects   bool     `json:"follow_cross_host_redirects"`
	UserAgent                  string   `json:"user_agent"`
	CandidateLimitPerIP        int      `json:"candidate_limit_per_ip"`
	JitsiPaths                 []string `json:"jitsi_paths"`
}

type Finding struct {
	Domain   string
	IP       string
	Evidence string
}

type State struct {
	LastScanFinishedAt int64  `json:"last_scan_finished_at"`
	SourceURL          string `json:"source_url"`
	IPCount            int    `json:"ip_count"`
	KnownDomainCount   int    `json:"known_domain_count"`
	FoundThisRun       int    `json:"found_this_run"`
}

var ipRegexp = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)

func defaultConfig() Config {
	return Config{
		SourceURL:                 "https://raw.githubusercontent.com/openlibrecommunity/twl/refs/heads/main/code/scan/out/verify/verified.txt",
		ScanIntervalSeconds:       21600,
		OutputFile:                "found_jitsi_domains.txt",
		DetailsFile:               "found_jitsi_details.tsv",
		StateFile:                 "scanner_state.json",
		LogFile:                   "jitsi_scanner.log",
		MaxWorkers:                64,
		ConnectTimeoutSeconds:     5,
		RequestTimeoutSeconds:     8,
		VerifyTLS:                 false,
		ProbeHTTP:                 true,
		ProbeHTTPS:                true,
		RequireDomainResolvesToIP: true,
		ForceProbeIP:              true,
		FollowCrossHostRedirects:  false,
		UserAgent:                 "jitsi-scanner-go/1.0",
		CandidateLimitPerIP:       80,
		JitsiPaths: []string{
			"/",
			"/config.js",
			"/interface_config.js",
			"/external_api.js",
		},
	}
}

func main() {
	configPath := flag.String("config", "config.json", "Path to JSON config file")
	once := flag.Bool("once", false, "Run one scan cycle and exit")
	writeDefaultConfig := flag.Bool("write-default-config", false, "Write a default config file and exit")
	flag.Parse()

	if *writeDefaultConfig {
		if err := writeDefaultConfigFile(*configPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %s\n", *configPath)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	closeLog, err := setupLogging(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer closeLog()

	if *once {
		if _, err := runOnce(cfg); err != nil {
			log.Printf("scan failed: %v", err)
			os.Exit(1)
		}
		return
	}
	runForever(cfg)
}

func writeDefaultConfigFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(defaultConfig(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = 1
	}
	if cfg.ConnectTimeoutSeconds < 1 {
		cfg.ConnectTimeoutSeconds = 1
	}
	if cfg.RequestTimeoutSeconds < 1 {
		cfg.RequestTimeoutSeconds = 1
	}
	if cfg.ScanIntervalSeconds < 1 {
		cfg.ScanIntervalSeconds = 1
	}
	return cfg, nil
}

func setupLogging(cfg Config) (func(), error) {
	if cfg.LogFile == "" {
		log.SetOutput(os.Stdout)
		log.SetFlags(log.LstdFlags)
		return func() {}, nil
	}
	if err := ensureParentDir(cfg.LogFile); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	log.SetOutput(io.MultiWriter(os.Stdout, file))
	log.SetFlags(log.LstdFlags)
	return func() { _ = file.Close() }, nil
}

func runForever(cfg Config) {
	for {
		started := time.Now()
		if _, err := runOnce(cfg); err != nil {
			log.Printf("scan cycle failed: %v", err)
		}
		sleepFor := time.Duration(cfg.ScanIntervalSeconds)*time.Second - time.Since(started)
		if sleepFor < time.Second {
			sleepFor = time.Second
		}
		log.Printf("Next scan in %s", sleepFor.Round(time.Second))
		time.Sleep(sleepFor)
	}
}

func runOnce(cfg Config) (int, error) {
	log.Printf("Downloading IP list from %s", cfg.SourceURL)
	text, err := fetchText(cfg.SourceURL, cfg)
	if err != nil {
		return 0, err
	}
	ips := parseIPs(text)
	log.Printf("Loaded %d IP addresses", len(ips))

	knownDomains, err := loadKnownDomains(cfg.OutputFile)
	if err != nil {
		return 0, err
	}

	jobs := make(chan string)
	results := make(chan []Finding)
	var wg sync.WaitGroup
	for i := 0; i < cfg.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				results <- scanIP(ip, cfg)
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	foundThisRun := 0
	scanned := 0
	for findings := range results {
		scanned++
		for _, finding := range findings {
			if knownDomains[finding.Domain] {
				continue
			}
			knownDomains[finding.Domain] = true
			if err := appendFinding(cfg.OutputFile, finding); err != nil {
				return foundThisRun, err
			}
			if cfg.DetailsFile != "" {
				if err := appendDetails(cfg.DetailsFile, finding); err != nil {
					return foundThisRun, err
				}
			}
			foundThisRun++
			log.Printf("Found Jitsi domain: %s (%s)", finding.Domain, finding.IP)
		}
		if scanned%100 == 0 {
			log.Printf("Progress: %d/%d IPs scanned", scanned, len(ips))
		}
	}

	state := State{
		LastScanFinishedAt: time.Now().Unix(),
		SourceURL:          cfg.SourceURL,
		IPCount:            len(ips),
		KnownDomainCount:   len(knownDomains),
		FoundThisRun:       foundThisRun,
	}
	if err := saveState(cfg.StateFile, state); err != nil {
		return foundThisRun, err
	}
	log.Printf("Scan finished: %d new domains found", foundThisRun)
	return foundThisRun, nil
}

func fetchText(rawURL string, cfg Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.RequestTimeoutSeconds)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)

	client := &http.Client{Timeout: time.Duration(cfg.RequestTimeoutSeconds) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected status from source URL: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func parseIPs(text string) []string {
	seen := make(map[string]bool)
	for _, match := range ipRegexp.FindAllString(text, -1) {
		ip := net.ParseIP(match)
		if ip == nil || ip.To4() == nil {
			continue
		}
		seen[ip.String()] = true
	}
	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		a := net.ParseIP(ips[i]).To4()
		b := net.ParseIP(ips[j]).To4()
		return bytes.Compare(a, b) < 0
	})
	return ips
}

func loadKnownDomains(path string) (map[string]bool, error) {
	domains := make(map[string]bool)
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return domains, nil
	}
	if err != nil {
		return domains, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if domain := normalizeHostname(fields[0]); domain != "" {
			domains[domain] = true
		}
	}
	return domains, scanner.Err()
}

func appendFinding(path string, finding Finding) error {
	return appendLine(path, finding.Domain+"\n")
}

func appendDetails(path string, finding Finding) error {
	line := fmt.Sprintf("%s\t%s\t%s\n", finding.Domain, finding.IP, finding.Evidence)
	return appendLine(path, line)
}

func appendLine(path string, line string) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(line); err != nil {
		return err
	}
	return file.Sync()
}

func saveState(path string, state State) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}

func scanIP(ip string, cfg Config) []Finding {
	findings := make([]Finding, 0)
	for _, domain := range candidateDomains(ip, cfg) {
		if finding, ok := validateJitsi(domain, ip, cfg); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func candidateDomains(ip string, cfg Config) []string {
	seen := make(map[string]bool)
	for _, domain := range ptrCandidates(ip) {
		seen[domain] = true
	}
	for _, domain := range certificateCandidates(ip, cfg) {
		seen[domain] = true
	}
	for _, domain := range redirectCandidates(ip, cfg) {
		seen[domain] = true
	}

	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	if cfg.CandidateLimitPerIP > 0 && len(domains) > cfg.CandidateLimitPerIP {
		domains = domains[:cfg.CandidateLimitPerIP]
	}
	return domains
}

func ptrCandidates(ip string) []string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	return normalizeHostnames(names)
}

func certificateCandidates(ip string, cfg Config) []string {
	dialer := &net.Dialer{Timeout: time.Duration(cfg.ConnectTimeoutSeconds) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	names := make([]string, 0)
	for _, cert := range conn.ConnectionState().PeerCertificates {
		names = append(names, cert.DNSNames...)
		if cert.Subject.CommonName != "" {
			names = append(names, cert.Subject.CommonName)
		}
	}
	return normalizeHostnames(names)
}

func redirectCandidates(ip string, cfg Config) []string {
	client := &http.Client{
		Timeout: time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(cfg.ConnectTimeoutSeconds) * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var names []string
	for _, scheme := range []string{"http", "https"} {
		rawURL := scheme + "://" + ip + "/"
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", cfg.UserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		location := resp.Header.Get("Location")
		_ = resp.Body.Close()
		if location == "" || resp.StatusCode < 300 || resp.StatusCode >= 400 {
			continue
		}
		parsed, err := url.Parse(location)
		if err != nil {
			continue
		}
		if parsed.Hostname() != "" {
			names = append(names, parsed.Hostname())
		}
	}
	return normalizeHostnames(names)
}

func normalizeHostnames(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		if host := normalizeHostname(value); host != "" {
			seen[host] = true
		}
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func normalizeHostname(value string) string {
	host := strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	if strings.HasPrefix(host, "*.") {
		host = strings.TrimPrefix(host, "*.")
	}
	if host == "" || !strings.Contains(host, ".") || len(host) > 253 {
		return ""
	}
	for _, r := range host {
		if r > 127 {
			return ""
		}
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return ""
		}
	}
	return host
}

func validateJitsi(domain string, ip string, cfg Config) (Finding, bool) {
	if cfg.RequireDomainResolvesToIP && !domainResolvesToIP(domain, ip) {
		return Finding{}, false
	}

	for _, scheme := range probeSchemes(cfg) {
		for _, path := range cfg.JitsiPaths {
			rawURL := scheme + "://" + domain + path
			status, body, finalHost, err := fetchURL(rawURL, domain, ip, cfg)
			if err != nil || status >= 500 {
				continue
			}
			if finalHost != "" && finalHost != domain && !cfg.FollowCrossHostRedirects {
				continue
			}
			if marker, ok := detectJitsi(path, body); ok {
				evidence := rawURL + " marker=" + marker
				if finalHost != "" && finalHost != domain {
					evidence += " final_host=" + finalHost
				}
				return Finding{Domain: domain, IP: ip, Evidence: evidence}, true
			}
		}
	}
	return Finding{}, false
}

func probeSchemes(cfg Config) []string {
	schemes := make([]string, 0, 2)
	if cfg.ProbeHTTPS {
		schemes = append(schemes, "https")
	}
	if cfg.ProbeHTTP {
		schemes = append(schemes, "http")
	}
	return schemes
}

func domainResolvesToIP(domain string, ip string) bool {
	resolved, err := net.LookupIP(domain)
	if err != nil {
		return false
	}
	for _, item := range resolved {
		if item.String() == ip {
			return true
		}
	}
	return false
}

func detectJitsi(path string, body string) (string, bool) {
	bodyLower := strings.ToLower(body)
	pathLower := strings.ToLower(path)

	if strings.Contains(pathLower, "external_api.js") {
		if strings.Contains(bodyLower, "jitsimeetexternalapi") ||
			strings.Contains(bodyLower, "jitsi-meet") {
			return "external_api.js", true
		}
		return "", false
	}

	if strings.Contains(pathLower, "interface_config.js") {
		if strings.Contains(bodyLower, "var interfaceconfig") &&
			(strings.Contains(bodyLower, "app_name") ||
				strings.Contains(bodyLower, "jitsi_watermark_link") ||
				strings.Contains(bodyLower, "provider_name")) &&
			strings.Contains(bodyLower, "jitsi") {
			return "interface_config.js", true
		}
		return "", false
	}

	if strings.Contains(pathLower, "config.js") {
		score := 0
		configMarkers := []string{
			"var config",
			"config =",
			"hosts:",
			"domain:",
			"bosh:",
			"websocket:",
			"muc:",
			"focususerjid",
			"p2p:",
			"/http-bind",
		}
		for _, marker := range configMarkers {
			if strings.Contains(bodyLower, marker) {
				score++
			}
		}
		if score >= 4 && (strings.Contains(bodyLower, "bosh:") ||
			strings.Contains(bodyLower, "/http-bind") ||
			strings.Contains(bodyLower, "xmpp-websocket")) {
			return "config.js", true
		}
		return "", false
	}

	if marker, ok := detectJitsiHTML(bodyLower); ok {
		return marker, true
	}

	return "", false
}

func detectJitsiHTML(bodyLower string) (string, bool) {
	if strings.Contains(bodyLower, "jitsimeetjs.app.renderentrypoint") &&
		strings.Contains(bodyLower, "jitsimeetjs.app.entrypoints.app") {
		return "jitsimeetjs_app", true
	}

	if strings.Contains(bodyLower, "lib-jitsi-meet.min.js") &&
		strings.Contains(bodyLower, "app.bundle.min.js") &&
		strings.Contains(bodyLower, "interface_config.js") &&
		strings.Contains(bodyLower, "config.js") {
		return "jitsi_assets", true
	}

	if strings.Contains(bodyLower, "jitsi videobridge") &&
		strings.Contains(bodyLower, "jitsi meet") &&
		(strings.Contains(bodyLower, "app.bundle.min.js") ||
			strings.Contains(bodyLower, "lib-jitsi-meet.min.js")) {
		return "jitsi_meta", true
	}

	if strings.Contains(bodyLower, "var config") &&
		strings.Contains(bodyLower, "var interfaceconfig") &&
		strings.Contains(bodyLower, "bosh:") &&
		strings.Contains(bodyLower, "muc:") &&
		strings.Contains(bodyLower, "app_name") &&
		strings.Contains(bodyLower, "jitsi") {
		return "inline_config_and_interface", true
	}

	return "", false
}

func fetchURL(rawURL string, probeDomain string, probeIP string, cfg Config) (int, string, string, error) {
	dialer := &net.Dialer{
		Timeout: time.Duration(cfg.ConnectTimeoutSeconds) * time.Second,
	}
	dialContext := dialer.DialContext
	if cfg.ForceProbeIP {
		dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if strings.EqualFold(host, probeDomain) {
				address = net.JoinHostPort(probeIP, port)
			}
			return dialer.DialContext(ctx, network, address)
		}
	}
	client := &http.Client{
		Timeout: time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS},
			DialContext:       dialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if cfg.FollowCrossHostRedirects {
				return nil
			}
			if req.URL == nil || !strings.EqualFold(req.URL.Hostname(), probeDomain) {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 512000)
	data, err := io.ReadAll(limited)
	if err != nil {
		return 0, "", "", err
	}
	finalHost := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalHost = strings.ToLower(resp.Request.URL.Hostname())
	}
	return resp.StatusCode, string(data), finalHost, nil
}
