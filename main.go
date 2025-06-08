package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

const (
	allowedZone = "pod.hetmer.net."
	upstreamDNS = "[2a09:e206:c1:ffff::1]:53"
	prefix      = "systemd-"
	listenAddr  = ":53"
	network     = "udp"
	negativeTTL = 60   // 1 minute
	answerTTL   = 300  // 5 minutes
)

type DNSHandler struct {
	allowedZone string
	prefix      string
	upstreamDNS string
}

func (h *DNSHandler) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	// Strip DO bit if present, since we don't support DNSSEC
	if opt := req.IsEdns0(); opt != nil {
		opt.Do() // ensure the bit is visible
		opt.SetDo(false)
	}

	if len(req.Question) == 0 {
		fmt.Println("\u26a0\ufe0f No questions in query")
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	q := req.Question[0]
	originalName := q.Name
	normalizedName := strings.ToLower(originalName)
	normalizedZone := strings.ToLower(h.allowedZone)

	if normalizedName == normalizedZone {
		fmt.Printf("\ud83d\udcbc Ignoring direct zone query: %s\n", originalName)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		m.Ns = append(m.Ns, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   h.allowedZone,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    negativeTTL,
			},
			Ns:      "dns-pod.hetmer.net.",
			Mbox:    "pod.hetmer.net.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  negativeTTL,
		})
		_ = w.WriteMsg(m)
		return
	}

	if !strings.HasSuffix(normalizedName, "."+normalizedZone) {
		fmt.Printf("\ud83d\udeab Blocked query: %s (not a subdomain of %s)\n", originalName, h.allowedZone)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		fmt.Printf("\ud83d\udcbc Ignoring non-A/AAAA query: %s [%d]\n", originalName, q.Qtype)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	newName, err := h.rewriteQuery(normalizedName, normalizedZone)
	if err != nil {
		fmt.Printf("\u274c Rewrite error: %v\n", err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	fmt.Printf("\ud83d\udd04 Rewriting: %s \u279e %s\n", originalName, newName)

	resp, err := forwardQuery(req, newName, h.upstreamDNS)
	if err != nil {
		fmt.Printf("\u274c Forward error: %v\n", err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	resp.SetReply(req)
	for i, ans := range resp.Answer {
		if strings.EqualFold(ans.Header().Name, newName) {
			resp.Answer[i].Header().Name = originalName
			resp.Answer[i].Header().Ttl = answerTTL
		}
	}
	for i, ns := range resp.Ns {
		if strings.EqualFold(ns.Header().Name, newName) {
			resp.Ns[i].Header().Name = originalName
			resp.Ns[i].Header().Ttl = answerTTL
		}
	}
	for i, extra := range resp.Extra {
		if strings.EqualFold(extra.Header().Name, newName) {
			resp.Extra[i].Header().Name = originalName
			resp.Extra[i].Header().Ttl = answerTTL
		}
	}

	_ = w.WriteMsg(resp)
}

func (h *DNSHandler) rewriteQuery(normalizedName, normalizedZone string) (string, error) {
	subdomain := strings.TrimSuffix(normalizedName, "."+normalizedZone)
	subdomain = strings.TrimSuffix(subdomain, ".")
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
		allowedZone: allowedZone,
		prefix:      prefix,
		upstreamDNS: upstreamDNS,
	}
	dns.HandleFunc(".", handler.handleDNS)
	server := &dns.Server{Addr: listenAddr, Net: network}
	fmt.Printf("\ud83c\udf38 DNS server is running on %s (%s)...\n", listenAddr, network)
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("\ud83d\udca5 Server failed: %v\n", err)
	}
}
