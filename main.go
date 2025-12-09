package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// ---------------------------------------------
// Configuration structures
// ---------------------------------------------

type ZoneConfig struct {
	Zone     string // normalized with trailing dot
	Prefix   string // optional override, fallback to handler.defaultPrefix
	Protocol string // udp/tcp
	Upstream string // host:port or [ipv6]:port
}

type DNSHandler struct {
	zones         map[string]ZoneConfig
	defaultPrefix string
	negativeTTL   uint32
	answerTTL     uint32
	listenAddr    string
}

// ---------------------------------------------
// Env utilities
// ---------------------------------------------

func getEnvWithDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	return defaultValue
}

func getEnvUint32WithDefault(key string, defaultValue uint32) uint32 {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		var result uint32
		_, err := fmt.Sscanf(value, "%d", &result)
		if err == nil {
			return result
		}
	}
	return defaultValue
}

// ---------------------------------------------
// Parse ZONES env variable
// Format:
//   ZONES=pod.hetmer.net.=udp:[ip]:53,net2.hetmer.net.=udp:10.42.0.1:53
//
// Optional prefixes:
//   ZONES=pod.hetmer.net.=systemd-:udp:[ip]:53
// ---------------------------------------------

func parseZoneEnv(env string) (map[string]ZoneConfig, error) {
	zones := make(map[string]ZoneConfig)

	if env == "" {
		return nil, fmt.Errorf("ZONES env var must not be empty")
	}

	entries := strings.Split(env, ",")
	for _, entry := range entries {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid ZONES entry: %s", entry)
		}

		zone := parts[0]
		if !strings.HasSuffix(zone, ".") {
			zone += "."
		}

		value := parts[1]

		prefix := ""
		protoUp := value

		// detect optional prefix:prefix:proto:upstream syntax
		if idx := strings.Index(value, ":"); idx != -1 {
			field1 := value[:idx]
			rest := value[idx+1:]

			// field1 could be a prefix OR a protocol
			if field1 == "udp" || field1 == "tcp" {
				// it's protocol
				protoUp = value
			} else {
				// it's prefix
				prefix = field1
				protoUp = rest
			}
		}

		// Now protoUp must start with proto:
		sub := strings.SplitN(protoUp, ":", 2)
		if len(sub) != 2 {
			return nil, fmt.Errorf("invalid upstream syntax in: %s", entry)
		}

		proto := sub[0]
		upstream := sub[1]

		zones[zone] = ZoneConfig{
			Zone:     zone,
			Prefix:   prefix,
			Protocol: proto,
			Upstream: upstream,
		}
	}

	return zones, nil
}

// ---------------------------------------------
// SOA creation per zone
// ---------------------------------------------

func (h *DNSHandler) createLocalSOA(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    h.negativeTTL,
		},
		Ns:      "dns-pod.hetmer.net.",
		Mbox:    "pod.hetmer.net.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  h.negativeTTL,
	}
}

// ---------------------------------------------
// Zone matching
// ---------------------------------------------

func (h *DNSHandler) selectZoneForName(name string) (*ZoneConfig, bool, bool) {
	name = strings.ToLower(name)

	for _, cfg := range h.zones {
		zone := strings.ToLower(cfg.Zone)

		// Apex: exact match
		if name == zone {
			return &cfg, true, true
		}
		// Subdomain: ends with ".zone"
		if strings.HasSuffix(name, "."+zone) {
			return &cfg, true, false
		}
	}

	return nil, false, false
}

// ---------------------------------------------
// Query rewriting
// ---------------------------------------------

func (h *DNSHandler) rewriteQuery(name string, cfg *ZoneConfig) (string, error) {
	name = strings.ToLower(name)
	zone := strings.ToLower(cfg.Zone)

	subdomain := strings.TrimSuffix(name, "."+zone)
	if subdomain == "" {
		return "", fmt.Errorf("empty subdomain after trimming zone")
	}

	prefix := cfg.Prefix
	if prefix == "" {
		prefix = h.defaultPrefix
	}

	return prefix + subdomain + ".", nil
}

// ---------------------------------------------
// Forward upstream
// ---------------------------------------------

func forwardQuery(originalReq *dns.Msg, name, proto, upstream string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, originalReq.Question[0].Qtype)
	m.Id = originalReq.Id
	m.RecursionDesired = true

	c := &dns.Client{Net: proto}

	resp, _, err := c.Exchange(m, upstream)
	if err != nil || resp == nil {
		return nil, fmt.Errorf("failed to query upstream %s://%s: %w", proto, upstream, err)
	}

	return resp, nil
}

// ---------------------------------------------
// Main DNS handler
// ---------------------------------------------

func (h *DNSHandler) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if opt := req.IsEdns0(); opt != nil {
		opt.SetDo(false)
	}

	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	q := req.Question[0]
	originalName := q.Name
	normalizedName := strings.ToLower(originalName)

	zoneCfg, ok, isApex := h.selectZoneForName(normalizedName)
	if !ok {
		// Not in any allowed zone → NXDOMAIN + local SOA
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		m.Ns = append(m.Ns, h.createLocalSOA("invalid."))
		_ = w.WriteMsg(m)
		return
	}

	// Apex handling
	if isApex {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeSuccess)

		if q.Qtype == dns.TypeSOA {
			m.Answer = append(m.Answer, h.createLocalSOA(zoneCfg.Zone))
		} else {
			m.Ns = append(m.Ns, h.createLocalSOA(zoneCfg.Zone))
		}

		_ = w.WriteMsg(m)
		return
	}

	// Only A/AAAA allowed
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		m.Ns = append(m.Ns, h.createLocalSOA(zoneCfg.Zone))
		_ = w.WriteMsg(m)
		return
	}

	newName, err := h.rewriteQuery(normalizedName, zoneCfg)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	resp, err := forwardQuery(req, newName, zoneCfg.Protocol, zoneCfg.Upstream)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	// Replace upstream SOA on NXDOMAIN
	if resp.Rcode == dns.RcodeNameError {
		resp.Ns = []dns.RR{}
		resp.Ns = append(resp.Ns, h.createLocalSOA(zoneCfg.Zone))
	}

	resp.SetReply(req)

	// Rewrite names and TTLs
	for i, ans := range resp.Answer {
		if strings.EqualFold(ans.Header().Name, newName) {
			resp.Answer[i].Header().Name = originalName
			resp.Answer[i].Header().Ttl = h.answerTTL
		}
	}
	for i, ns := range resp.Ns {
		if strings.EqualFold(ns.Header().Name, newName) {
			resp.Ns[i].Header().Name = originalName
			resp.Ns[i].Header().Ttl = h.answerTTL
		}
	}
	for i, extra := range resp.Extra {
		if strings.EqualFold(extra.Header().Name, newName) {
			resp.Extra[i].Header().Name = originalName
			resp.Extra[i].Header().Ttl = h.answerTTL
		}
	}

	_ = w.WriteMsg(resp)
}

// ---------------------------------------------
// Main
// ---------------------------------------------

func main() {
	zones, err := parseZoneEnv(getEnvWithDefault("ZONES", ""))
	if err != nil {
		panic(err)
	}

	handler := &DNSHandler{
		zones:         zones,
		defaultPrefix: getEnvWithDefault("DEFAULT_PREFIX", "systemd-"),
		negativeTTL:   getEnvUint32WithDefault("NEGATIVE_TTL", 60),
		answerTTL:     getEnvUint32WithDefault("ANSWER_TTL", 300),
		listenAddr:    getEnvWithDefault("LISTEN_ADDR", ":53"),
	}

	dns.HandleFunc(".", handler.handleDNS)
	server := &dns.Server{Addr: handler.listenAddr, Net: "udp"}

	fmt.Printf("DNS server running on %s with %d zones\n", handler.listenAddr, len(zones))

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
