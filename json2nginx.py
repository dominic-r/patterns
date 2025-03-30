import json
import os
import re
import logging
from pathlib import Path
from collections import defaultdict
from functools import lru_cache
from typing import List, Dict, Optional, Tuple

# --- Configuration ---
LOG_LEVEL = logging.INFO  # DEBUG, INFO, WARNING, ERROR
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/nginx"))
MAPS_FILE = OUTPUT_DIR / "waf_maps.conf"
RULES_FILE = OUTPUT_DIR / "waf_rules.conf"

# Unsupported Nginx directives (expand as needed)
UNSUPPORTED_PATTERNS = [
    "@pmFromFile",  # No direct file lookups in Nginx map
]

# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# --- Utility Functions ---
def load_owasp_rules(file_path: Path) -> List[Dict]:
    """Loads OWASP rules from a JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        logger.error(f"Error loading rules from {file_path}: {e}")
        raise  # Re-raise to prevent continuing

@lru_cache(maxsize=256)  # Increased cache size
def validate_regex(pattern: str) -> bool:
    """Validates a regex pattern (basic check)."""
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        logger.warning(f"Invalid regex: {pattern} - {e}")
        return False

def _sanitize_pattern(pattern: str) -> str:
    """Internal helper to clean and escape patterns for Nginx."""
    pattern = pattern.replace("@rx ", "").strip() # Remove ModSecurity @rx
     # Remove case-insensitive flag (?i) as Nginx uses ~* for that
    pattern = re.sub(r"\(\?i\)", "", pattern)

    # Convert $ to \$
    pattern = pattern.replace("$", r"\$")

    # Convert { or { to {
    pattern = re.sub(r"&l(?:brace|cub);?", r"{", pattern)
    pattern = re.sub(r"&r(?:brace|cub);?", r"}", pattern)

    # Remove unnecessary \.*
    pattern = re.sub(r"\\\.\*", r"\.*", pattern)
    pattern = re.sub(r"(?<!\\)\.(?![\w])", r"\.", pattern)  # Escape dots

    # Replace non-capturing groups (?:...) with capturing groups (...)
    pattern = re.sub(r"\(\?:", "(", pattern)

    return pattern

def sanitize_pattern(pattern: str, location: str) -> Optional[str]:
    """
    Sanitizes a pattern for use in an Nginx map directive.
    Returns the sanitized pattern, or None if the pattern is unsupported.
    """
    # Skip unsupported patterns.
    for unsupported in UNSUPPORTED_PATTERNS:
        if unsupported in pattern:
            logger.warning(f"Skipping unsupported pattern: {pattern}")
            return None

    # Limit pattern length before processing to avoid excessive computation
    if len(pattern) > 1000:
        logger.warning(f"Pattern too long (before processing), truncating: {pattern[:50]}...")
        pattern = pattern[:1000]

    # Sanitize the pattern
    pattern = _sanitize_pattern(pattern)

    # Escape special characters for Nginx map (most importantly, the ~)
    # We use re.escape, but *selectively* unescape key regex metacharacters.
    pattern = re.escape(pattern)
    # Unescape:  \.  \(  \)  \[  \]  \|  \?  \*  \+  \{  \}  \^  \$  \\
    pattern = re.sub(r'\\([.()[\]|?*+{}^$\\])', r'\1', pattern)
    
    # Final check for quotes to prevent NGINX errors
    pattern = pattern.replace('"', '\\"')  # Escape all quotes
    
    # Final limit on pattern length to ensure NGINX can handle it
    if len(pattern) > 900:  # More conservative limit
        logger.warning(f"Pattern too long after processing, truncating: {pattern[:50]}...")
        pattern = pattern[:900]
    
    return pattern

def generate_nginx_waf(rules: List[Dict]) -> None:
    """Generates Nginx WAF configuration (maps and rules)."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    categorized_rules: Dict[str, Dict[str, str]] = defaultdict(lambda: defaultdict(str)) # category -> location

    for rule in rules:
        rule_id = rule.get("id", "no_id")  # Get rule ID
        category = rule.get("category", "generic").lower()
        location = rule.get("location", "request-uri").lower() # set a default location
        pattern = rule["pattern"]
        severity = rule.get("severity", "medium").lower() # get severity

        sanitized_pattern = sanitize_pattern(pattern, location)
        if not sanitized_pattern or not validate_regex(sanitized_pattern):
            continue  # Skip invalid or unsupported patterns

        # Additional validation to prevent regex pattern issues
        if len(sanitized_pattern) > 900:  # Reduced from 1000 to be more conservative
            logger.warning(f"Pattern too long, truncating: {rule_id}")
            sanitized_pattern = sanitized_pattern[:900]

        if location == "request-uri":
            variable = "$request_uri"
        elif location == "query-string":
            variable = "$args"  #  Use $args for query string
        elif location == "user-agent":
            variable = "$http_user_agent"
        elif location == "host":
            variable = "$http_host"
        elif location == "referer":
            variable = "$http_referer"
        elif location == "content-type":
            variable = "$http_content_type"
        # Add more location mappings here
        else:
            logger.warning(f"Unsupported location: {location} for rule: {rule_id}")
            continue

        # Extra safety check for quotes and line length
        if '"' in sanitized_pattern or len(sanitized_pattern) > 900:
            logger.warning(f"Potentially problematic pattern in rule {rule_id}, applying extra sanitization")
            sanitized_pattern = sanitized_pattern.replace('"', '\\"')
            sanitized_pattern = sanitized_pattern[:900]

        # Add rule based on severity and location
        categorized_rules[category][variable] += f'  "~*{sanitized_pattern}" {severity};\n' # set severity as value


    # --- Generate Maps (waf_maps.conf) ---
    try:
        with open(MAPS_FILE, "w", encoding="utf-8") as f:
            f.write("# Nginx WAF Maps (Generated by json2nginx.py)\n\n")
            
            # Add initialization for the waf_blocked variable
            f.write("# Initialize the blocked status variable\n")
            f.write("map $remote_addr $waf_blocked {\n")
            f.write('  default "";\n')
            f.write("}\n\n")

            for category, location_rules in categorized_rules.items():
                for location, rules in location_rules.items():
                    # Create a map for each location variable and category
                    location_var = location  # This is already the Nginx variable (e.g., $request_uri)
                    f.write(f"map {location_var} $waf_{category} {{\n")
                    f.write('  default "";\n')  # default value empty
                    f.write(f"  # Rules for {location}\n")
                    f.write(rules)  # Write the collected rules for this location
                    f.write("}\n\n")

        logger.info(f"Generated Nginx map file: {MAPS_FILE}")
    except IOError as e:
        logger.error(f"Error writing to {MAPS_FILE}: {e}")
        raise

    # --- Generate Rules (waf_rules.conf) ---
    try:
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            f.write("# Nginx WAF Rules (Generated by json2nginx.py)\n\n")
            f.write("# Include this file in your 'location' block.\n\n")
            
            # Initialize the waf_blocked variable at the start if it's not already set
            f.write("# Initialize waf_blocked variable if not already set\n")
            f.write('set $waf_blocked "";\n\n')

            # iterate for each rule
            for category, location_rules in categorized_rules.items():
                # set map to correct WAF block
                map_variable = f"$waf_{category}"
                # create conditions based on priority
                f.write(f'if ({map_variable} = "high") {{\n  return 403;\n}}\n')
                
                # Use literal string for waf_blocked to avoid NameError
                f.write(f'if ({map_variable} = "medium") {{\n  set $waf_blocked "$waf_blocked'+'medium-{0},".format(category);\n}}\n')
                f.write(f'if ({map_variable} = "low") {{\n  set $waf_blocked "$waf_blocked'+'low-{0},".format(category);\n}}\n\n')
            
            # Add a single add_header directive at the end
            f.write('# Add a single header with all blocked rule categories if any\n')
            f.write('if ($waf_blocked != "") {\n')
            f.write('  add_header X-WAF-Blocked $waf_blocked always;\n')
            f.write('}\n')

        logger.info(f"Generated Nginx rules file: {RULES_FILE}")

    except IOError as e:
        logger.error(f"Error writing to {RULES_FILE}: {e}")
        raise


    # --- Generate README ---
    readme_file = OUTPUT_DIR / "README.md"
    try:
        with open(readme_file, "w", encoding="utf-8") as f:
            f.write("# Nginx WAF Configuration\n\n")
            f.write("This directory contains Nginx WAF configuration files generated from OWASP rules.\n\n")
            f.write("## Usage\n\n")
            f.write("1. **Include `waf_maps.conf` in your `http` block:**\n")
            f.write("   ```nginx\n")
            f.write("   http {\n")
            f.write("       include /path/to/waf_patterns/nginx/waf_maps.conf;\n")
            f.write("       # ... other http configurations ...\n")
            f.write("   }\n")
            f.write("   ```\n\n")
            f.write("2. **Include `waf_rules.conf` in your `location` block:**\n")
            f.write("   ```nginx\n")
            f.write("   server {\n")
            f.write("       # ... other server configurations ...\n")
            f.write("       location / {\n")
            f.write("           include /path/to/waf_patterns/nginx/waf_rules.conf;\n")
            f.write("           # ... other location configurations ...\n")
            f.write("       }\n")
            f.write("   }\n")
            f.write("   ```\n\n")
            f.write("3. **Reload Nginx:**\n")
            f.write("   ```bash\n")
            f.write("   sudo nginx -t && sudo systemctl reload nginx\n")
            f.write("   ```\n\n")
            f.write("## Important Notes:\n\n")
            f.write("* **Important:** The `add_header` directive can only be used inside a location or server block, not in an http block.\n") 
            f.write("* **Testing is Crucial:**  Thoroughly test your WAF configuration with a variety of requests (both legitimate and malicious) to ensure it's working correctly and not causing false positives.\n")
            f.write("* **False Positives:**  WAF rules, especially those based on regex, can sometimes block legitimate traffic.  Monitor your Nginx logs and adjust the rules as needed.\n")
            f.write("* **Performance:** Complex regexes can impact performance.  Use the simplest regex that accurately matches the threat.\n")
            f.write("* **Updates:**  Regularly update the OWASP rules (by re-running `owasp2json.py` and `json2nginx.py`) to stay protected against new threats.\n")
            f.write("* **This is not a complete WAF:** This script provides a basic WAF based on pattern matching.  For more comprehensive protection, consider using a dedicated WAF solution like Nginx App Protect or ModSecurity.\n")

    except IOError as e:
        logger.error(f"Error writing to {readme_file}: {e}")
        raise

def main():
    """Main function."""
    try:
        logger.info("Loading OWASP rules...")
        owasp_rules = load_owasp_rules(INPUT_FILE)
        logger.info(f"Loaded {len(owasp_rules)} rules.")

        logger.info("Generating Nginx WAF configuration...")
        generate_nginx_waf(owasp_rules)

        logger.info("Nginx WAF generation complete.")
    except Exception as e:
        logger.critical(f"Script failed: {e}")
        exit(1)  # Exit with an error code

if __name__ == "__main__":
    main()
