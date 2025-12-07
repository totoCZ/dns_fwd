package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

type DNSHandler struct {
	allowedZone string
	prefix      string
	upstreamDNS string
	negativeTTL uint32
	answerTTL   uint32
	listenAddr  string
	network     string
}

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

// Helper function to create the correct local SOA record
func (h *DNSHandler) createLocalSOA() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   h.allowedZone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    h.negativeTTL, // Use the configured TTL for the SOA record itself
		},
		Ns:      "dns-pod.hetmer.net.",
		Mbox:    "pod.hetmer.net.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  h.negativeTTL, // Crucial for defining the negative cache TTL
	}
}

func (h *DNSHandler) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	// Strip DO bit if present, since we don't support DNSSEC
	if opt := req.IsEdns0(); opt != nil {
		opt.SetDo(false)
	}

	if len(req.Question) == 0 {
		fmt.Println("⚠ No questions in query")
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	q := req.Question[0]
	originalName := q.Name
	normalizedName := strings.ToLower(originalName)
	normalizedZone := h.allowedZone

	// --- FIX 1: Correctly respond to direct zone queries (SOA) ---
	if normalizedName == normalizedZone {
		fmt.Printf("📋 Direct zone query: %s. Responding with local SOA.\n", originalName)
		m := new(dns.Msg)
		
		// If requesting the SOA record specifically, put it in the ANSWER section.
		if q.Qtype == dns.TypeSOA {
			m.SetRcode(req, dns.RcodeSuccess)
			m.Answer = append(m.Answer, h.createLocalSOA())
		} else {
			// For any other query type (A, AAAA, etc.) for the zone apex, 
			// return NOERROR with no data (NODATA) and the SOA in the Authority section.
			m.SetRcode(req, dns.RcodeSuccess)
			m.Ns = append(m.Ns, h.createLocalSOA())
		}
		
		_ = w.WriteMsg(m)
		return
	}

	if !strings.HasSuffix(normalizedName, "."+normalizedZone) {
		fmt.Printf("🚫 Blocked query: %s (not a subdomain of %s)\n", originalName, h.allowedZone)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		// For an outright blocked query, assert authority with your SOA as well!
		m.Ns = append(m.Ns, h.createLocalSOA()) 
		_ = w.WriteMsg(m)
		return
	}

	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		fmt.Printf("📋 Ignoring non-A/AAAA query: %s [%d]\n", originalName, q.Qtype)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		m.Ns = append(m.Ns, h.createLocalSOA()) // Add SOA for negative caching
		_ = w.WriteMsg(m)
		return
	}

	newName, err := h.rewriteQuery(normalizedName, normalizedZone)
	if err != nil {
		fmt.Printf("❌ Rewrite error: %v\n", err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	fmt.Printf("🔄 Rewriting: %s → %s\n", originalName, newName)

	resp, err := forwardQuery(req, newName, h.upstreamDNS)
	if err != nil {
		fmt.Printf("❌ Forward error: %v\n", err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	// --- FIX 2: Check for NXDOMAIN and replace the Authority Section ---
	if resp.Rcode == dns.RcodeNameError {
		fmt.Printf("✅ Upstream returned NXDOMAIN for %s. Asserting local authority for negative caching.\n", newName)
		
		// Clear the upstream's Authority Section (removes the public/root SOA)
		resp.Ns = []dns.RR{} 
		
		// Add your local SOA to the Authority Section to enforce local TTL
		resp.Ns = append(resp.Ns, h.createLocalSOA()) 
	} 
	
	resp.SetReply(req)
	
	// Apply header and TTL rewrites
	for i, ans := range resp.Answer {
		if strings.EqualFold(ans.Header().Name, newName) {
			resp.Answer[i].Header().Name = originalName
			resp.Answer[i].Header().Ttl = h.answerTTL
		}
	}
	// Rewriting Authority and Extra sections' names for glue records is less critical here,
	// but keeping the logic to overwrite TTLs for cleanliness.
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

func (h *DNSHandler) rewriteQuery(normalizedName, normalizedZone string) (string, error) {
	subdomain := strings.TrimSuffix(normalizedName, "."+normalizedZone)
	if subdomain == "" {
		return "", fmt.Errorf("empty subdomain after trimming zone")
	}
	return h.prefix + subdomain + ".", nil
}

func forwardQuery(originalReq *dns.Msg, name string, upstreamDNS string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, originalReq.Question[0].Qtype)
	m.Id = originalReq.Id
	m.RecursionDesired = true

	c := new(dns.Client)
	resp, _, err := c.Exchange(m, upstreamDNS)
	if err != nil || resp == nil {
		return nil, fmt.Errorf("failed to exchange with upstream DNS: %w", err)
	}
	return resp, nil
}

func main() {
	handler := &DNSHandler{
		allowedZone: getEnvWithDefault("ALLOWED_ZONE", "pod.hetmer.net."),
		prefix:      getEnvWithDefault("PREFIX", "systemd-"),
		upstreamDNS: getEnvWithDefault("UPSTREAM_DNS", "[2a09:e206:c1:ffff::1]:53"),
		negativeTTL: getEnvUint32WithDefault("NEGATIVE_TTL", 60),
		answerTTL:   getEnvUint32WithDefault("ANSWER_TTL", 300),
		listenAddr:  getEnvWithDefault("LISTEN_ADDR", ":53"),
		network:     getEnvWithDefault("NETWORK", "udp"),
	}
	dns.HandleFunc(".", handler.handleDNS)
	server := &dns.Server{Addr: handler.listenAddr, Net: handler.network}
	fmt.Printf("🌸 DNS server is running on %s (%s)...\n", handler.listenAddr, handler.network)
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("💥 Server failed: %v\n", err)
	}
}