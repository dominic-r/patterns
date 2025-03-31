# Nginx WAF Configuration

This directory contains Nginx WAF configuration files generated from OWASP rules.

## Usage

1. **Include `waf_maps.conf` in your `http` block:**
   ```nginx
   http {
       include /path/to/waf_patterns/nginx/waf_maps.conf;
       # ... other http configurations ...
   }
   ```

2. **Include `waf_rules.conf` in your `server` or `location` block:**
   ```nginx
   server {
       # ... other server configurations ...
       include /path/to/waf_patterns/nginx/waf_rules.conf;
   }
   ```

3. **Reload Nginx:**
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```

## Important Notes:

* **Testing is Crucial:**  Thoroughly test your WAF configuration with a variety of requests (both legitimate and malicious) to ensure it's working correctly and not causing false positives.
* **False Positives:**  WAF rules, especially those based on regex, can sometimes block legitimate traffic.  Monitor your Nginx logs and adjust the rules as needed.
* **Performance:** Complex regexes can impact performance.  Use the simplest regex that accurately matches the threat.
* **Updates:**  Regularly update the OWASP rules (by re-running `owasp2json.py` and `json2nginx.py`) to stay protected against new threats.
* **This is not a complete WAF:** This script provides a basic WAF based on pattern matching.  For more comprehensive protection, consider using a dedicated WAF solution like Nginx App Protect or ModSecurity.
