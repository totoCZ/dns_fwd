# 🌸 DNS Rewriter Server

A tiny custom DNS proxy written in Go~! 🐾 It listens for A and AAAA queries in a specific DNS zone and rewrites them with a prefix before forwarding to an upstream resolver. Perfect for redirecting service names like `foo.pod.hetmer.net.` to something like `systemd-foo`~! 💫

## ✨ Features
- Listens on UDP port 53
- Only accepts queries for `*.pod.hetmer.net.`
- Rewrites query names with a prefix (e.g., `systemd-`)
- Forwards the rewritten query to an upstream IPv6 DNS server
- Rejects non-A/AAAA queries and invalid zones
- Adds TTLs and fixes up response names for compatibility

## 🧙 How It Works
1. Incoming query is checked:
   - Must be A or AAAA
   - Must match the allowed zone
2. Name is rewritten: `foo.pod.hetmer.net.` -> `systemd-foo.`
3. New query is sent to an upstream DNS server
4. Answer is rewritten back to original name
5. Response is returned to the client

## ⚙️ Configuration
You can tweak it using env vars:

```bash
export ALLOWED_ZONE="pod.example.com."
export UPSTREAM_DNS="192.168.1.1:53"
export PREFIX="kawaii-"
export LISTEN_ADDR=":53"
export NETWORK="udp"
export NEGATIVE_TTL=60
export ANSWER_TTL=300
```

## 🚀 Running
```bash
go build -o dnsproxy
sudo ./dnsproxy
```

Make sure port 53 isn't already used (e.g., by `systemd-resolved`)~!

## 🧪 Testing
Use `dig` to try it out:

```bash
dig foo.pod.hetmer.net. A @localhost
```

This should get rewritten to `systemd-foo.` and forwarded upstream~ 🌈

## 📦 Dependencies
- [miekg/dns](https://github.com/miekg/dns) — A DNS library in Go

Install via:
```bash
go get github.com/miekg/dns
```

## 💖 License
MIT License~ Do what you want, just don’t blame me if the DNS faeries misbehave~ 🧚‍♀️

---
Made with love, Go, and a sprinkle of DNS pixie dust~ ✨

