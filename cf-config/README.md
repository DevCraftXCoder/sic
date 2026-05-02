# SIC — IP Allowlist Configs

This directory contains IP allowlist configuration for restricting access to the SIC admin UI.

## Files

- **ip-allowlist.json** — Structured allowlist. Edit the `allow` array to add your IPs/CIDRs. Set `deny_default: true` to block all unlisted IPs.
- **nginx-ip-allowlist.conf** — Ready-to-include nginx geo block. After editing, `nginx -t` to validate and `nginx -s reload` to apply.

## Quick Start (nginx)

1. Add your IP to both `ip-allowlist.json` and `nginx-ip-allowlist.conf`:
   ```
   "203.0.113.5/32"   # in JSON allow array
   203.0.113.5/32  1; # in nginx geo block
   ```
2. Include the conf in your nginx server block:
   ```nginx
   include /path/to/sic/cf-config/nginx-ip-allowlist.conf;
   ```
3. Protect the proxy location:
   ```nginx
   location / {
       if ($sic_allowed = 0) { return 403; }
       proxy_pass http://127.0.0.1:9888;
   }
   ```
4. Test and reload: `sudo nginx -t && sudo nginx -s reload`

## Cloudflare (alternative)

If SIC is behind Cloudflare, use a WAF Custom Rule instead of nginx:
- Field: `ip.src`
- Operator: `is not in`
- Values: your allowed IPs
- Action: Block
