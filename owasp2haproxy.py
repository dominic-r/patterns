import os
import json
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Constants (configurable via environment variables)
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/haproxy/"))  # Output directory
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))  # Input JSON file


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


def generate_haproxy_conf(rules):
    """
    Generate HAProxy ACL rules from OWASP rules.
    """
    try:
        # Ensure the output directory exists
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"[+] Created or verified directory: {OUTPUT_DIR}")

        # Define the output file path
        config_file = OUTPUT_DIR / "waf.acl"

        # Write HAProxy ACL rules to the file
        with open(config_file, "w") as f:
            f.write("# HAProxy WAF ACL rules\n\n")
            for rule in rules:
                try:
                    category = rule["category"]
                    pattern = rule["pattern"]
                    f.write(f"acl block_{category} hdr_sub(User-Agent) -i {pattern}\n")
                    f.write(f"http-request deny if block_{category}\n\n")
                except KeyError as e:
                    logging.warning(f"[!] Skipping invalid rule (missing key: {e}): {rule}")
                    continue

        logging.info(f"[+] HAProxy WAF rules generated at {config_file}")
    except Exception as e:
        logging.error(f"[!] Error generating HAProxy configuration: {e}")
        raise


def main():
    """
    Main function to execute the script.
    """
    try:
        logging.info("[*] Loading OWASP rules...")
        owasp_rules = load_owasp_rules(INPUT_FILE)

        logging.info(f"[*] Generating HAProxy WAF configs from {len(owasp_rules)} rules...")
        generate_haproxy_conf(owasp_rules)

        logging.info("[✔] HAProxy WAF configurations generated successfully.")
    except Exception as e:
        logging.critical(f"[!] Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
