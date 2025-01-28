# Nginx WAF Configuration

This directory contains Nginx WAF configuration files generated from OWASP rules.
You can include these files in your existing Nginx configuration to enhance security.

## Usage
1. Include the `waf_maps.conf` file in your `nginx.conf` *inside the `http` block*:
   ```nginx
   http {
       include /path/to/waf_patterns/nginx/waf_maps.conf;
       # ... other http configurations ...
   }
   ```
2. Include the `waf_rules.conf` file in your `server` block:
   ```nginx
   server {
       # ... other server configurations ...
       include /path/to/waf_patterns/nginx/waf_rules.conf;
   }
   ```
3. Reload Nginx to apply the changes:
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```

## Notes
- The rules use `map` directives for efficient pattern matching. The maps are defined in the `waf_maps.conf` file.
- The rules (if statements) are defined in the `waf_rules.conf` file.
- Blocked requests return a `403 Forbidden` response by default.
- You can enable logging for blocked requests by uncommenting the `access_log` line.
