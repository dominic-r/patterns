import json
import os
import re
from collections import defaultdict
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Paths
INPUT_FILE = Path("owasp_rules.json")  # Input JSON file
OUTPUT_DIR = Path("waf_patterns/apache")  # Output directory for Apache configs

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ModSecurity rule template
MODSEC_RULE_TEMPLATE = (
    'SecRule REQUEST_URI "{pattern}" "id:{rule_id},phase:1,deny,status:403,log,msg:\'{category} attack detected\'"\n'
)

UNSUPPORTED_PATTERNS = ["@pmFromFile", "!@eq", "!@within", "@lt"]


def load_owasp_rules(file_path):
    """
    Load OWASP rules from a JSON file.
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"[!] Input file not found: {file_path}")
        raise
    except json.JSONDecodeError:
        logging.error(f"[!] Invalid JSON in file: {file_path}")
        raise
    except Exception as e:
        logging.error(f"[!] Error loading OWASP rules: {e}")
        raise


def validate_regex(pattern):
    """
    Validate regex pattern to ensure it is compatible with ModSecurity.
    """
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        logging.warning(f"[!] Skipping invalid regex: {pattern} - {e}")
        return False


def sanitize_pattern(pattern):
    """
    Sanitize unsupported patterns and directives for ModSecurity.
    """
    if any(directive in pattern for directive in UNSUPPORTED_PATTERNS):
        logging.warning(f"[!] Skipping unsupported pattern: {pattern}")
        return None

    # Handle regex patterns prefixed with @rx
    if pattern.startswith("@rx "):
        return pattern.replace("@rx ", "").strip()

    return pattern


def generate_apache_waf(rules):
    """
    Generate Apache ModSecurity configuration files from OWASP rules.
    """
    categorized_rules = defaultdict(set)
    rule_id_counter = 1000  # Starting rule ID

    # Group rules by category and ensure deduplication
    for rule in rules:
        try:
            category = rule.get("category", "generic").lower()
            pattern = rule["pattern"]

            sanitized_pattern = sanitize_pattern(pattern)
            if sanitized_pattern and validate_regex(sanitized_pattern):
                categorized_rules[category].add((sanitized_pattern, rule_id_counter))
                rule_id_counter += 1
            else:
                logging.warning(f"[!] Skipping invalid or unsupported rule: {pattern}")
        except KeyError as e:
            logging.warning(f"[!] Skipping malformed rule (missing key: {e}): {rule}")
            continue

    # Write rules to per-category configuration files
    for category, patterns in categorized_rules.items():
        output_file = OUTPUT_DIR / f"{category}.conf"

        try:
            with open(output_file, "w") as f:
                f.write(f"# Apache ModSecurity rules for {category.upper()}\n")
                f.write("SecRuleEngine On\n\n")

                # Write rules with unique IDs
                for pattern, rule_id in patterns:
                    rule = MODSEC_RULE_TEMPLATE.format(
                        pattern=re.escape(pattern), rule_id=rule_id, category=category
                    )
                    f.write(rule)

            logging.info(f"[+] Generated {output_file} ({len(patterns)} patterns)")
        except IOError as e:
            logging.error(f"[!] Failed to write to {output_file}: {e}")
            raise


def main():
    """
    Main function to execute the script.
    """
    try:
        logging.info("[*] Loading OWASP rules...")
        owasp_rules = load_owasp_rules(INPUT_FILE)

        logging.info(f"[*] Generating Apache WAF configs from {len(owasp_rules)} rules...")
        generate_apache_waf(owasp_rules)

        logging.info("[✔] Apache ModSecurity configurations generated successfully.")
    except Exception as e:
        logging.critical(f"[!] Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
