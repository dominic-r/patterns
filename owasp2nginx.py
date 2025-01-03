import json
import os
import logging
from pathlib import Path
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Constants (configurable via environment variables)
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))  # Input JSON file
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/nginx"))  # Output directory

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


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


def generate_nginx_waf(rules):
    """
    Generate Nginx WAF configuration files from OWASP rules.
    """
    categorized_rules = defaultdict(list)

    # Group rules by category
    for rule in rules:
        try:
            category = rule.get("category", "generic").lower()
            pattern = rule["pattern"]
            categorized_rules[category].append(pattern)
        except KeyError as e:
            logging.warning(f"[!] Skipping invalid rule (missing key: {e}): {rule}")
            continue

    # Convert to Nginx conf files
    for category, patterns in categorized_rules.items():
        output_file = OUTPUT_DIR / f"{category}.conf"

        try:
            with open(output_file, "w") as f:
                f.write(f"# Nginx WAF rules for {category.upper()}\n")
                f.write("location / {\n")
                f.write("    set $attack_detected 0;\n\n")

                # Write rules as regex checks
                for pattern in patterns:
                    f.write(f'    if ($request_uri ~* "{pattern}") {{\n')
                    f.write("        set $attack_detected 1;\n")
                    f.write("    }\n\n")

                # Block the request if an attack is detected
                f.write("    if ($attack_detected = 1) {\n")
                f.write("        return 403;\n")
                f.write("    }\n")
                f.write("}\n")

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

        logging.info(f"[*] Generating Nginx WAF configs from {len(owasp_rules)} rules...")
        generate_nginx_waf(owasp_rules)

        logging.info("[✔] Nginx WAF configurations generated successfully.")
    except Exception as e:
        logging.critical(f"[!] Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
