# Nginx WAF Rule Snippets

This directory contains Nginx WAF rule snippets generated from OWASP rules.
You can include these snippets in your existing Nginx configuration to enhance security.

## Usage
1. Include the rule snippets in your `server` or `location` block:
   ```nginx
   server {
       # Your existing configuration
       include /path/to/waf_patterns/nginx/*.conf;
   }
   ```
2. Reload Nginx to apply the changes:
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```

## Notes
- The rules use `map` directives for efficient pattern matching.
- Blocked requests return a `403 Forbidden` response by default.
- You can enable logging for blocked requests by uncommenting the `access_log` line.
