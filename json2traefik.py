import os
import json
from pathlib import Path
from typing import List, Dict, Set
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Constants
OUTPUT_DIR = Path("waf_patterns/traefik/")  # Output directory for Traefik configs


def load_owasp_rules(file_path: Path) -> List[Dict]:
    """
    Load OWASP rules from a JSON file.

    Args:
        file_path (Path): Path to the JSON file containing OWASP rules.

    Returns:
        List[Dict]: List of OWASP rules.

    Raises:
        SystemExit: If the file is not found or contains invalid JSON.
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"[-] Error: File '{file_path}' not found.")
        exit(1)
    except json.JSONDecodeError:
        logging.error(f"[-] Error: Invalid JSON in '{file_path}'.")
        exit(1)
    except Exception as e:
        logging.error(f"[-] Unexpected error loading OWASP rules: {e}")
        exit(1)


def generate_traefik_conf(rules: List[Dict]) -> None:
    """
    Generate Traefik middleware configuration from OWASP rules.

    Args:
        rules (List[Dict]): List of OWASP rules.

    Raises:
        SystemExit: If there is an error writing to the output file.
    """
    try:
        # Ensure the output directory exists
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        config_file = OUTPUT_DIR / "middleware.toml"

        with open(config_file, "w") as f:
            f.write("[http.middlewares]\n\n")

            # Group rules by category
            grouped_rules: Dict[str, List[Dict]] = {}
            for rule in rules:
                category = rule.get("category", "default")
                if category not in grouped_rules:
                    grouped_rules[category] = []
                grouped_rules[category].append(rule)

            # Write grouped rules to the TOML file
            for category, rules_in_category in grouped_rules.items():
                f.write(f"[http.middlewares.bad_bot_block_{category}]\n")
                f.write(f"  [http.middlewares.bad_bot_block_{category}.plugin.badbot]\n")
                f.write("    userAgent = [\n")

                # Use a set to deduplicate rules
                unique_rules: Set[str] = set()
                for rule in rules_in_category:
                    # Escape special characters in the pattern
                    pattern = rule["pattern"].replace('"', '\\"').replace("\\", "\\\\")
                    unique_rules.add(f'      "{pattern}"')

                f.write(",\n".join(unique_rules) + "\n")
                f.write("    ]\n\n")

        logging.info(f"[+] Traefik WAF rules generated at {config_file}")
    except IOError as e:
        logging.error(f"[-] Error writing to file: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"[-] Unexpected error generating Traefik config: {e}")
        exit(1)


def main() -> None:
    """
    Main function to execute the script.
    """
    try:
        logging.info("[*] Loading OWASP rules...")
        owasp_rules = load_owasp_rules(Path("owasp_rules.json"))

        logging.info(f"[*] Generating Traefik WAF configs from {len(owasp_rules)} rules...")
        generate_traefik_conf(owasp_rules)

        logging.info("[✔] Traefik WAF configurations generated successfully.")
    except Exception as e:
        logging.critical(f"[!] Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()