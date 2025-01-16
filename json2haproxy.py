import os
import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Constants (configurable via environment variables)
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/haproxy/"))  # Output directory
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))  # Input JSON file

UNSUPPORTED_PATTERNS = ["@pmFromFile", "!@eq", "!@within", "@lt", "@ge", "@gt", "@eq"]

def load_owasp_rules(file_path: Path) -> List[Dict]:
    """
    Load OWASP rules from a JSON file.
    
    Args:
        file_path (Path): Path to the JSON file containing OWASP rules.
    
    Returns:
        List[Dict]: List of OWASP rules.
    
    Raises:
        FileNotFoundError: If the input file is not found.
        json.JSONDecodeError: If the JSON file is invalid.
        Exception: For any other errors during file loading.
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

def validate_regex(pattern: str) -> bool:
    """
    Validate regex pattern for HAProxy.
    
    Args:
        pattern (str): Regex pattern to validate.
    
    Returns:
        bool: True if the regex is valid, False otherwise.
    """
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        logging.warning(f"[!] Invalid regex: {pattern} - {e}")
        return False

def sanitize_pattern(pattern: str) -> Optional[str]:
    """
    Sanitize unsupported patterns and directives for HAProxy ACLs.
    
    Args:
        pattern (str): The pattern to sanitize.
    
    Returns:
        Optional[str]: The sanitized pattern, or None if the pattern is unsupported.
    """
    # Skip unsupported patterns
    if any(directive in pattern for directive in UNSUPPORTED_PATTERNS):
        logging.warning(f"[!] Skipping unsupported pattern: {pattern}")
        return None

    # Remove @rx (regex indicator) for HAProxy compatibility
    pattern = pattern.replace("@rx ", "").strip()

    # Remove case-insensitive flag (?i) as HAProxy uses -i for that
    pattern = re.sub(r"\(\?i\)", "", pattern)

    # Convert &dollar; to \$
    pattern = pattern.replace("&dollar;", r"\$")

    # Convert &lbrace; or &lcub; to {
    pattern = re.sub(r"&l(?:brace|cub);?", r"{", pattern)
    pattern = re.sub(r"&r(?:brace|cub);?", r"}", pattern)

    # Remove unnecessary \.*
    pattern = re.sub(r"\\\.\*", r"\.*", pattern)
    pattern = re.sub(r"(?<!\\)\.(?![\w])", r"\.", pattern)  # Escape dots

    # Replace non-capturing groups (?:...) with capturing groups (...)
    pattern = re.sub(r"\(\?:", "(", pattern)

    return pattern

def generate_haproxy_conf(rules: List[Dict]) -> None:
    """
    Generate HAProxy ACL rules from OWASP rules.
    
    Args:
        rules (List[Dict]): List of OWASP rules.
    
    Raises:
        Exception: If there is an error generating the HAProxy configuration.
    """
    try:
        # Ensure the output directory exists
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"[+] Created or verified directory: {OUTPUT_DIR}")

        # Define the output file path
        config_file = OUTPUT_DIR / "waf.acl"
        unique_rules = set()

        # Write HAProxy ACL rules to the file
        with open(config_file, "w") as f:
            f.write("# HAProxy WAF ACL rules\n\n")
            for rule in rules:
                try:
                    category = rule["category"].lower()
                    pattern = rule["pattern"]

                    sanitized_pattern = sanitize_pattern(pattern)
                    if sanitized_pattern and validate_regex(sanitized_pattern):
                        if (category, sanitized_pattern) not in unique_rules:
                            f.write(f"acl block_{category} hdr_sub(User-Agent) -i {sanitized_pattern}\n")
                            f.write(f"http-request deny if block_{category}\n\n")
                            unique_rules.add((category, sanitized_pattern))
                    else:
                        logging.warning(f"[!] Skipping invalid rule: {pattern}")
                except KeyError as e:
                    logging.warning(f"[!] Skipping invalid rule (missing key: {e}): {rule}")
                    continue

        logging.info(f"[+] HAProxy WAF rules generated at {config_file}")
    except Exception as e:
        logging.error(f"[!] Error generating HAProxy configuration: {e}")
        raise

def main() -> None:
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