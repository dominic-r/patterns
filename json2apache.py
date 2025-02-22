import json
import os
import re
from collections import defaultdict
import logging
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from functools import lru_cache

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

# Unsupported patterns for ModSecurity
UNSUPPORTED_PATTERNS = ["@pmFromFile", "!@eq", "!@within", "@lt"]


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


@lru_cache(maxsize=None)
def validate_regex(pattern: str) -> bool:
    """
    Validate regex pattern to ensure it is compatible with ModSecurity.

    Args:
        pattern (str): Regex pattern to validate.

    Returns:
        bool: True if the regex is valid, False otherwise.
    """
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        logging.warning(f"[!] Skipping invalid regex: {pattern} - {e}")
        return False


def sanitize_pattern(pattern: str) -> Optional[str]:
    """
    Sanitize unsupported patterns and directives for ModSecurity.

    Args:
        pattern (str): The pattern to sanitize.

    Returns:
        Optional[str]: The sanitized pattern, or None if the pattern is unsupported.
    """
    # Skip unsupported patterns
    if any(directive in pattern for directive in UNSUPPORTED_PATTERNS):
        logging.warning(f"[!] Skipping unsupported pattern: {pattern}")
        return None

    # Handle regex patterns prefixed with @rx
    if pattern.startswith("@rx "):
        return pattern.replace("@rx ", "").strip()

    return pattern


def generate_apache_waf(rules: List[Dict]) -> None:
    """
    Generate Apache ModSecurity configuration files from OWASP rules.

    Args:
        rules (List[Dict]): List of OWASP rules.

    Raises:
        IOError: If there is an error writing to the output files.
    """
    categorized_rules: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)
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


def load_json(file_path):
    """
    Load and parse JSON file.

    Args:
        file_path (Path): Path to the JSON file to be loaded.

    Returns:
        dict: Parsed JSON content.
    """
    with file_path.open('r', encoding='utf-8') as f:
        return json.load(f)

def write_rules_to_file(rules, output_path):
    """
    Write ModSecurity rules to a file.

    Args:
        rules (list): List of ModSecurity rules as strings.
        output_path (Path): Path to the output file.
    """
    with output_path.open('w', encoding='utf-8') as f:
        f.writelines(rules)

def main():
    json_data = load_json(INPUT_FILE)
    
    rules = []
    rule_id = 1000  # Initial rule ID

    # Check if json_data is a dictionary and contains the 'rules' key
    if isinstance(json_data, dict):
        for rule in json_data.get('rules', []):
            pattern = rule.get('pattern')
            category = rule.get('category')

            if not pattern or any(unsupported in pattern for unsupported in UNSUPPORTED_PATTERNS):
                logging.info(f"[!] Skipping unsupported pattern: {pattern}")
                continue

            if validate_regex(pattern):
                rules.append(MODSEC_RULE_TEMPLATE.format(pattern=pattern, rule_id=rule_id, category=category))
                rule_id += 1
    else:
       logging.error("[!] Invalid JSON format: Expected a dictionary with a 'rules' key.")
       return
   
    output_file_path = OUTPUT_DIR / "rules.conf"
    write_rules_to_file(rules, output_file_path)
    logging.info(f"[+] Generated rules.conf in {output_file_path}")

if __name__ == "__main__":
    main()
