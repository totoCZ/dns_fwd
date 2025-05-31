package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Configuration constants
const (
	allowedZone = "pod.hetmer.net." // Only rewrite domains from this zone
	upstreamDNS = "10.0.240.1:53"   // Upstream resolver to query
	prefix      = "systemd-"        // Prefix added to the subdomain
	listenAddr  = ":53"             // Server listening address
	network     = "udp"             // Network protocol
)

// DNSHandler handles incoming DNS requests
type DNSHandler struct {
	allowedZone string
	prefix      string
	upstreamDNS string
}

// handleDNS processes DNS queries
func (h *DNSHandler) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	// Ensure there's at least one question in the query
	if len(req.Question) == 0 {
		fmt.Println("⚠️ No questions in query")
		// Send a DNS SERVFAIL response if no questions are present
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		if err := w.WriteMsg(m); err != nil {
			fmt.Printf("❌ Failed to write SERVFAIL response: %v\n", err)
		}
		return
	}

	q := req.Question[0]
	originalName := q.Name
	normalizedName := strings.ToLower(originalName)
	normalizedZone := strings.ToLower(h.allowedZone)

	// Check if the query belongs to the allowed zone
	if !strings.HasSuffix(normalizedName, normalizedZone) {
		fmt.Printf("🚫 Blocked query: %s (not in %s)\n", originalName, h.allowedZone)
		// Send a DNS NXDOMAIN response for queries outside the allowed zone
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		if err := w.WriteMsg(m); err != nil {
			fmt.Printf("❌ Failed to write NXDOMAIN response: %v\n", err)
		}
		return
	}

	// Extract subdomain and rewrite query name
	newName, err := h.rewriteQuery(normalizedName, normalizedZone)
	if err != nil {
		fmt.Printf("❌ Rewrite error: %v\n", err)
		// Send a DNS SERVFAIL response if rewriting fails
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		if err := w.WriteMsg(m); err != nil {
			fmt.Printf("❌ Failed to write SERVFAIL response: %v\n", err)
		}
		return
	}

	fmt.Printf("🔄 Rewriting: %s ➜ %s\n", originalName, newName)

	// Forward query to upstream DNS, preserving the original request's ID
	resp, err := forwardQuery(req, newName, h.upstreamDNS)
	if err != nil {
		fmt.Printf("❌ Forward error: %v\n", err)
		// Send a DNS SERVFAIL response if forwarding fails
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		if err := w.WriteMsg(m); err != nil {
			fmt.Printf("❌ Failed to write SERVFAIL response: %v\n", err)
		}
		return
	}

	// Crucial: Set the response's header (including ID) to match the original request
	// This ensures the client receives a response with the expected ID, resolving the "ID mismatch" warning.
	resp.SetReply(req)

	// Restore original name in response answers
	// Iterate through all answer RRs and update their names if they match the rewritten name
	for i, ans := range resp.Answer {
		if strings.EqualFold(ans.Header().Name, newName) {
			resp.Answer[i].Header().Name = originalName
		}
	}
	// Also restore original name in authority section
	for i, ns := range resp.Ns {
		if strings.EqualFold(ns.Header().Name, newName) {
			resp.Ns[i].Header().Name = originalName
		}
	}
	// Also restore original name in extra section
	for i, extra := range resp.Extra {
		if strings.EqualFold(extra.Header().Name, newName) {
			resp.Extra[i].Header().Name = originalName
		}
	}


	// Write the modified response back to the client
	if err := w.WriteMsg(resp); err != nil {
		fmt.Printf("❌ Failed to write response: %v\n", err)
	}
}

// rewriteQuery rewrites the subdomain by adding the prefix
func (h *DNSHandler) rewriteQuery(normalizedName, normalizedZone string) (string, error) {
	// Remove the allowed zone and trailing dot
	subdomain := strings.TrimSuffix(normalizedName, normalizedZone)
	subdomain = strings.TrimSuffix(subdomain, ".")
	if subdomain == "" {
		return "", fmt.Errorf("empty subdomain after trimming zone")
	}

	// Construct new query name by adding the prefix and ensuring a trailing dot
	return h.prefix + subdomain + ".", nil
}

// forwardQuery sends the query to the upstream DNS server
// It now accepts the original *dns.Msg to copy its ID.
func forwardQuery(originalReq *dns.Msg, name string, upstreamDNS string) (*dns.Msg, error) {
	// Create a new message for the upstream query, copying the original request's ID
	m := new(dns.Msg)
	m.SetQuestion(name, originalReq.Question[0].Qtype) // Use the original question type
	m.Id = originalReq.Id                               // Crucial: Copy the original request's ID
	m.RecursionDesired = true                           // Request recursion from upstream

	// Create a new DNS client
	c := new(dns.Client)
	// Exchange the query with the upstream DNS server
	resp, _, err := c.Exchange(m, upstreamDNS)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange with upstream DNS: %w", err)
	}
	// Check if the response is nil, which can happen on certain errors
	if resp == nil {
		return nil, fmt.Errorf("upstream DNS returned a nil response")
	}
	return resp, nil
}

func main() {
	// Initialize DNS handler with configuration
	handler := &DNSHandler{
		allowedZone: allowedZone,
		prefix:      prefix,
		upstreamDNS: upstreamDNS,
	}

	// Register DNS handler for all queries (represented by ".")
	dns.HandleFunc(".", handler.handleDNS)

	// Create and start the DNS server
	server := &dns.Server{Addr: listenAddr, Net: network}
	fmt.Printf("🌸 DNS server is running on %s (%s)...\n", listenAddr, network)
	// ListenAndServe blocks until an error occurs
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("💥 Server failed: %v\n", err)
	}
}
