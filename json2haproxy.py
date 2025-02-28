import os
import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from functools import lru_cache

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Constants (configurable via environment variables)
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/haproxy/"))  # Output directory
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))  # Input JSON file

UNSUPPORTED_PATTERNS = ["@pmFromFile", "@detectSQLi", "@validateByteRange"] # Add more unsupported patterns

# Operator mapping (ModSecurity to HAProxy) - Added more mappings
OPERATOR_MAP = {
    "@streq": "str -m str",
    "@ipMatch": "src_ip",
    "@endsWith": "str -m end",
    "@contains": "str -m sub",
    "!@eq": "str -m !str",  # Handle negation
    "!@within": "str -m !reg",  # Approximate !@within (requires regex)
    "@lt": "<",
    "@ge": ">=",
    "@gt": ">",
    "@eq": "==",
}


def load_owasp_rules(file_path: Path) -> List[Dict]:
    """
    Load OWASP rules from a JSON file.
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError as e:
        logging.error(f"[!] Input file not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"[!] Invalid JSON in file: {file_path}")
        raise
    except Exception as e:
        logging.error(f"[!] Error loading OWASP rules: {e}")
        raise

@lru_cache(maxsize=None)
def validate_regex(pattern: str) -> bool:
    """
    Validate regex pattern for HAProxy.  Added complexity check
    """
    try:
        # Simple complexity check (can be improved)
        if pattern.count(".*") > 5:
            logging.warning(f"[!] Regex too complex: {pattern}")
            return False

        re.compile(pattern)
        return True
    except re.error as e:
        logging.warning(f"[!] Invalid regex: {pattern} - {e}")
        return False

def sanitize_pattern(pattern: str) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Sanitize and convert ModSecurity patterns to HAProxy.
    Returns: sanitized pattern, ACL type, and transformed pattern (if needed)
    """
    acl_type = "hdr_reg"  # Default to regex matching
    transformed_pattern = None # optional transformation
    original_pattern = pattern # store original for logging
    int_comp_pattern = None # store the integer pattern

    for modsecurity_op, haproxy_op in OPERATOR_MAP.items():
        if pattern.startswith(modsecurity_op):
             # handle 'str' and 'int' matching in a different way

             if haproxy_op in ['<','>=','>','==']:
                 acl_type = "int"
                 int_comp_pattern = pattern.replace(modsecurity_op, haproxy_op).strip()
                 pattern = None # set to None to avoid regex validation

                 return pattern, acl_type, transformed_pattern

             acl_type = "hdr_sub"  # String matching
             pattern = pattern.replace(modsecurity_op, haproxy_op).strip()
             return pattern, acl_type, transformed_pattern

    # Skip unsupported patterns with more detailed logging
    for directive in UNSUPPORTED_PATTERNS:
        if directive in pattern:
            logging.warning(f"[!] Skipping unsupported pattern (contains {directive}): {pattern}")
            return None, acl_type, transformed_pattern # Indicate skip

    if "@rx" in pattern: # only remove @rx for REGEX cases to reduce bugs
        acl_type = "hdr_reg"
        pattern = pattern.replace("@rx ", "").strip()

        # Remove case-insensitive flag (?i) as HAProxy uses -i for that
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
    else:
        acl_type = "hdr_sub" # assume it is a normal comparison

    return pattern, acl_type, transformed_pattern # indicate success


def generate_haproxy_conf(rules: List[Dict]) -> None:
    """
    Generate HAProxy ACL rules from OWASP rules with prioritization and parameter selection.
    """
    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"[+] Created or verified directory: {OUTPUT_DIR}")

        config_file = OUTPUT_DIR / "waf.acl"
        acl_rules = {}  # Dict to store ACL rule definitions based on 'location'
        all_acl_names = [] # Store a full list of acl names for final deny

        int_comp_rules = []   # Collect the integer comparison rules
        # Initialize lists for different deny actions
        deny_high = []
        log_medium = []
        tarpit_low = []
        all_deny_actions = {
            "deny_high" : deny_high,
            "log_medium" : log_medium,
            "tarpit_low" : tarpit_low
        }

        unique_rules = set() # Prevent duplication rules

        # Process each rule
        for rule in rules:
            try:
                rule_id = rule.get("id", "no_id")  # Get ID, default "no_id"
                category = rule["category"].lower()
                location = rule.get("location", "User-Agent")  # Get location, default User-Agent
                pattern = rule["pattern"]
                severity = rule.get("severity", "medium").lower()  # severity for different actions

                sanitized_pattern, acl_type, transformed_pattern = sanitize_pattern(pattern)

                if acl_type == "int":  # Handle integer comparisons
                    if sanitized_pattern: # create the int condition pattern direct
                        action_string = "deny" if severity == "high" else "log" if severity == "medium" else "tarpit"

                        int_comp_rules.append(f"http-request {action_string} if {{ {location} {sanitized_pattern} }}") # Append direct the rule
                    else:
                        logging.warning(f"[!] Skipping integer rule with invalid pattern: {pattern}")
                elif sanitized_pattern and validate_regex(sanitized_pattern): # continue to the other filters when integer is not valid
                    acl_name = f"block_{category}_{rule_id}"  # Unique ACL name including ID

                    if acl_name not in all_acl_names:
                        all_acl_names.append(acl_name)  # Add to the list of ACLs

                        # Build the ACL rule string based on the 'location'
                        acl_rule_string = None # Set the initial state

                        if location == "Request-URI":
                            acl_rule_string = f"acl {acl_name} path_reg -i {sanitized_pattern}"
                        elif location == "Query-String":
                            acl_rule_string = f"acl {acl_name} query_reg -i {sanitized_pattern}"
                        elif location == "Host":
                            acl_rule_string = f"acl {acl_name} hdr_reg(Host) -i {sanitized_pattern}"
                        elif location == "Content-Type":
                            acl_rule_string = f"acl {acl_name} hdr_reg(Content-Type) -i {sanitized_pattern}"
                        elif location == "Referer":
                            acl_rule_string = f"acl {acl_name} hdr_reg(Referer) -i {sanitized_pattern}"
                        else: # Default case: User-Agent
                            if acl_type == 'hdr_reg':
                                acl_rule_string = f"acl {acl_name} hdr_reg(User-Agent) -i {sanitized_pattern}"
                            else: # hdr_sub
                                acl_rule_string = f"acl {acl_name} hdr_sub(User-Agent) -i {sanitized_pattern}"

                        if acl_rule_string:  # Check that a rule string has a value.
                            # Get the corresponding action based on severity
                            if severity == "high":
                                deny_high.append(acl_name)
                            elif severity == "medium":
                                log_medium.append(acl_name)
                            elif severity == "low":
                                tarpit_low.append(acl_name)

                            if location not in acl_rules:
                                acl_rules[location] = []  # Initialize if it is not already existent

                            acl_rules[location].append(acl_rule_string) # Append rule
                else:
                    logging.warning(f"[!] Skipping invalid rule: {pattern}")

            except KeyError as e:
                logging.warning(f"[!] Skipping invalid rule (missing key: {e}): {rule}")
                continue

        # Write HAProxy ACL rules to the file
        with open(config_file, "w") as f:
            f.write("# HAProxy WAF ACL rules\n\n")

            # Write integer rules
            if int_comp_rules:
                 f.write("# Integer Comparison Rules\n")
                 for int_rule in int_comp_rules:
                     f.write(f"{int_rule}\n")
                 f.write("\n")
            # Write all ACL definitions by location
            for location, rules in acl_rules.items():
                f.write(f"# Rules for {location}\n")
                for acl_rule in rules:
                    f.write(f"{acl_rule}\n")
                f.write("\n")

            f.write("\n")
            # Add all the actions based on rules
            for action, rules in all_deny_actions.items():
                action_string = 'deny' if action == "deny_high" else 'log' if action == "log_medium" else 'tarpit'
                f.write(f"# {action.split('_')[1].capitalize()} Severity Rules ({action_string.capitalize()})\n") # comment action
                if rules:
                    f.write(f"http-request {action_string} if {' or '.join(rules)}\n")
                f.write("\n")

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
