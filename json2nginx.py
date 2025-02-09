import json
import os
import re
import logging
from pathlib import Path
from collections import defaultdict
from functools import lru_cache

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Input and output paths
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/nginx"))
MAPS_FILE = OUTPUT_DIR / "waf_maps.conf"
RULES_FILE = OUTPUT_DIR / "waf_rules.conf"


# Create output directory if it doesn't exist
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_owasp_rules(file_path):
    """Load OWASP rules from a JSON file."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Input file not found: {file_path}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in file: {file_path}")
        raise


def validate_regex(pattern):
    """Validate if a pattern is a valid regex."""
    try:
        _compile_pattern(pattern)
        return True
    except re.error:
        return False


def sanitize_pattern(pattern):
    """Wrapper function to use caching for patterns."""
    return _sanitize_pattern(pattern)


def generate_nginx_waf(rules):
    """Generate Nginx WAF configuration snippets from OWASP rules."""
    categorized_rules = defaultdict(set)

    # Group rules by category
    for rule in rules:
        category = rule.get("category", "generic").lower()
        pattern = rule.get("pattern")

        sanitized_pattern = sanitize_pattern(pattern)
        if sanitized_pattern:
            categorized_rules[category].add(sanitized_pattern)
        else:
            logging.warning(f"Invalid or unsupported pattern skipped: {pattern}")

    # Write map definitions to a dedicated file
    try:
        with open(MAPS_FILE, "w") as f:
            f.write("# Nginx WAF Maps Definitions\n")
            f.write("# Automatically generated from OWASP rules.\n\n")
            f.write("http {\n")
            for category, patterns in categorized_rules.items():
               f.write(f"  map $request_uri $waf_block_{category} {{\n")
               f.write("      default 0;\n")
               for pattern in patterns:
                 escaped_pattern = pattern.replace('"', '\\"')
                 f.write(f'      "~*{escaped_pattern}" 1;\n')
               f.write("  }\n\n")
            f.write("}\n")

        logging.info(f"Generated {MAPS_FILE} containing map definitions")
    except IOError as e:
          logging.error(f"Failed to write {MAPS_FILE}: {e}")


    # Write if blocks to a dedicated file
    try:
        with open(RULES_FILE, "w") as f:
            f.write("# Nginx WAF Rules\n")
            f.write("# Automatically generated from OWASP rules.\n")
            f.write("# Include this file inside server block\n\n")
            f.write("  # WAF rules\n")
            for category in categorized_rules.keys():
                f.write(f"    if ($waf_block_{category}) {{\n")
                f.write("      return 403;\n")
                f.write("      # Log the blocked request (optional)\n")
                f.write("      # access_log /var/log/nginx/waf_blocked.log;\n")
                f.write("    }\n\n")

        logging.info(f"Generated {RULES_FILE} containing rules")
    except IOError as e:
        logging.error(f"Failed to write {RULES_FILE}: {e}")

    # Generate a README file with usage instructions
    readme_file = OUTPUT_DIR / "README.md"
    with open(readme_file, "w") as f:
        f.write("# Nginx WAF Configuration\n\n")
        f.write("This directory contains Nginx WAF configuration files generated from OWASP rules.\n")
        f.write("You can include these files in your existing Nginx configuration to enhance security.\n\n")
        f.write("## Usage\n")
        f.write("1. Include the `waf_maps.conf` file in your `nginx.conf` *inside the `http` block*:\n")
        f.write("   ```nginx\n")
        f.write("   http {\n")
        f.write("       include /path/to/waf_patterns/nginx/waf_maps.conf;\n")
        f.write("       # ... other http configurations ...\n")
        f.write("   }\n")
        f.write("   ```\n")
        f.write("2. Include the `waf_rules.conf` file in your `server` block:\n")
        f.write("   ```nginx\n")
        f.write("   server {\n")
        f.write("       # ... other server configurations ...\n")
        f.write("       include /path/to/waf_patterns/nginx/waf_rules.conf;\n")
        f.write("   }\n")
        f.write("   ```\n")
        f.write("3. Reload Nginx to apply the changes:\n")
        f.write("   ```bash\n")
        f.write("   sudo nginx -t && sudo systemctl reload nginx\n")
        f.write("   ```\n")
        f.write("\n## Notes\n")
        f.write("- The rules use `map` directives for efficient pattern matching. The maps are defined in the `waf_maps.conf` file.\n")
        f.write("- The rules (if statements) are defined in the `waf_rules.conf` file.\n")
        f.write("- Blocked requests return a `403 Forbidden` response by default.\n")
        f.write("- You can enable logging for blocked requests by uncommenting the `access_log` line.\n")


def main():
    """Main function to load rules and generate Nginx configurations."""
    try:
        logging.info("Loading OWASP rules...")
        owasp_rules = load_owasp_rules(INPUT_FILE)

        logging.info(f"Generating Nginx WAF configs from {len(owasp_rules)} rules...")
        generate_nginx_waf(owasp_rules)

        logging.info("Nginx WAF configurations generated successfully.")
    except Exception as e:
        logging.critical(f"Script failed: {e}")
        exit(1)

@lru_cache(maxsize=128)
def _compile_pattern(pattern):
    """Compile the regex pattern with caching to avoid recompilation."""
    return re.compile(pattern)

@lru_cache(maxsize=128)
def _sanitize_pattern(pattern):
    """Sanitize and validate OWASP patterns for Nginx compatibility."""
    if any(keyword in pattern for keyword in ["@pmFromFile", "!@eq", "!@within", "@lt"]):
        logging.warning(f"Skipping unsupported pattern: {pattern}")
        return None

    if pattern.startswith("@rx "):
        sanitized_pattern = pattern.replace("@rx ", "").strip()
    else:
        sanitized_pattern = pattern

    if validate_regex(sanitized_pattern):
        return re.escape(sanitized_pattern).replace(r'\@', '@')
    else:
        logging.warning(f"Invalid regex in pattern: {sanitized_pattern}")
        return None


if __name__ == "__main__":
    main()