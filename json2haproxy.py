import os
import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from functools import lru_cache

# --- Configuration ---
LOG_LEVEL = logging.INFO  # Adjust as needed (DEBUG, INFO, WARNING, ERROR)
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/haproxy/"))
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))

UNSUPPORTED_PATTERNS = [
    "@pmFromFile", "@detectSQLi", "@validateByteRange", "@detectXSS",  # Core unsupported
    # Add any other unsupported patterns discovered during testing
]

# Operator Mapping:  ModSecurity -> HAProxy
OPERATOR_MAP = {
    # String Comparisons
    "@streq": "str -m str",
    "@endsWith": "str -m end",
    "@contains": "str -m sub",
    "!@eq": "str -m !str",  # Negated string equality
    "!@within": "str -m !reg", # Negated regex (approximate)
    # Integer Comparisons (These are handled separately)
    "@lt": "<",
    "@ge": ">=",
    "@gt": ">",
    "@eq": "==",
    # IP address matching
    "@ipMatch": "src_ip",
}


# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Utility Functions ---
@lru_cache(maxsize=None)  # Cache regex compilation for performance
def validate_regex(pattern: str) -> bool:
    """Validates a regex pattern and checks for excessive complexity."""
    try:
        if pattern.count(".*") > 5:  # Basic complexity check
            logger.warning(f"Regex potentially too complex: {pattern}")
            #  Optionally return False here to *reject* complex regexes
        re.compile(pattern)
        return True
    except re.error as e:
        logger.warning(f"Invalid regex: {pattern} - {e}")
        return False

def load_owasp_rules(file_path: Path) -> List[Dict]:
    """Loads OWASP rules from the JSON file."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, Exception) as e:
        logger.error(f"Error loading rules from {file_path}: {e}")
        raise  # Re-raise to prevent the script from continuing

def _sanitize_regex_pattern(pattern: str) -> str:
    """Helper function to clean up regex patterns."""
    pattern = pattern.replace("@rx ", "").strip()
    pattern = re.sub(r"\(\?i\)", "", pattern)    # Remove (?i)
    pattern = pattern.replace("$", r"\$") # $ -> \$
    pattern = re.sub(r"&l(?:brace|cub);?", r"{", pattern) # {
    pattern = re.sub(r"&r(?:brace|cub);?", r"}", pattern) # }
    pattern = re.sub(r"\\\.\*", r"\.*", pattern)      # Remove unnecessary escapes
    pattern = re.sub(r"(?<!\\)\.(?![\w])", r"\.", pattern)  # Escape .
    pattern = re.sub(r"\(\?:", "(", pattern)  # (?: -> (
    return pattern


def sanitize_pattern(pattern: str, location: str) -> Tuple[Optional[str], str]:
    """
    Sanitizes and converts a ModSecurity pattern to its HAProxy equivalent.
    Returns: (sanitized_pattern, acl_type)  or (None, "") if unsupported.
    """
    original_pattern = pattern  # Keep for logging

    # 1. Handle ModSecurity operators *first*.
    for modsec_op, haproxy_op in OPERATOR_MAP.items():
        if pattern.startswith(modsec_op):
            if haproxy_op in ("<", ">=", ">", "=="):  # Integer comparisons
                # Integer comparisons are handled *separately*
                return pattern.replace(modsec_op, haproxy_op).strip(), "int"
            else:  # String comparisons
                return pattern.replace(modsec_op, haproxy_op).strip(), "hdr_sub"

    # 2. Check for unsupported patterns *after* operator handling.
    for directive in UNSUPPORTED_PATTERNS:
        if directive in pattern:
            logger.warning(f"Skipping unsupported pattern (contains {directive}): {original_pattern}")
            return None, ""

    # 3. Handle regular expressions (@rx)
    if "@rx" in pattern:
        return _sanitize_regex_pattern(pattern), "hdr_reg"

    # 4. If no operator and no @rx, assume it's a simple string match
    return pattern, "hdr_sub"


def generate_haproxy_conf(rules: List[Dict]) -> None:
    """Generates the HAProxy WAF configuration (waf.acl)."""

    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        config_file = OUTPUT_DIR / "waf.acl"

        acl_rules: Dict[str, List[str]] = {}  # { location: [acl_rules] }
        int_rules: List[str] = []
        deny_high: List[str] = []
        log_medium: List[str] = []
        tarpit_low: List[str] = []

        # Process each OWASP rule
        for rule in rules:
            rule_id = rule.get("id", "no_id")
            category = rule.get("category", "uncategorized").lower()
            location = rule.get("location", "User-Agent").lower() #important! lowercase
            pattern = rule["pattern"]
            severity = rule.get("severity", "medium").lower()

            sanitized_pattern, acl_type = sanitize_pattern(pattern, location)

            if sanitized_pattern is None:  # Unsupported/invalid pattern
                continue

            if acl_type == "int": # Int comparison
                action = "deny" if severity == "high" else "log" if severity == "medium" else "tarpit"
                # Special cases: some locations cannot be used directly
                if location in ("query-string", "request-uri"):
                    int_rules.append(f"http-request {action} if {{ {location} {sanitized_pattern} }}")
                else:
                    int_rules.append(f"http-request {action} if {{ {location},{sanitized_pattern} }}")

            elif acl_type in ("hdr_reg", "hdr_sub"):  # String comparison
                acl_name = f"block_{category}_{rule_id}"

                # Build the ACL rule string
                if location == "request-uri":
                    acl_string = f"acl {acl_name} path_reg -i {sanitized_pattern}"
                elif location == "query-string":
                     # No direct query_reg in HAProxy.  Need to use path, url, or url_param
                     acl_string = f"acl {acl_name} url_param_reg -i {sanitized_pattern}"
                elif location in ("host", "content-type", "referer","user-agent"):
                     hdr_func = "hdr_reg" if acl_type == "hdr_reg" else "hdr_sub"
                     acl_string = f"acl {acl_name} {hdr_func}({location.replace('-','')}) -i {sanitized_pattern}"
                else:
                    logger.warning(f"Unsupported location: {location} for rule: {rule_id}")
                    continue  # Skip unsupported locations

                if location not in acl_rules:
                    acl_rules[location] = []
                acl_rules[location].append(acl_string)


                if severity == "high":
                    deny_high.append(acl_name)
                elif severity == "medium":
                    log_medium.append(acl_name)
                elif severity == "low":
                    tarpit_low.append(acl_name)

        # Write the configuration to the file
        with open(config_file, "w") as f:
            f.write("# HAProxy WAF ACL rules\n\n")

            # Integer Comparison Rules (if any)
            if int_rules:
                f.write("# Integer Comparison Rules\n")
                for rule in int_rules:
                    f.write(f"{rule}\n")
                f.write("\n")

            # ACL Rules (by location)
            for location, rules in acl_rules.items():
                f.write(f"# Rules for {location.title()}\n") # title()
                for rule in rules:
                    f.write(f"{rule}\n")
                f.write("\n")

            # Deny/Action Logic
            f.write("# Deny/Action Logic\n")
            if deny_high:
                f.write(f"http-request deny if {' or '.join(deny_high)}\n")
            if log_medium:
                f.write(f"http-request log if {' or '.join(log_medium)}\n")
            if tarpit_low:
                f.write(f"http-request tarpit if {' or '.join(tarpit_low)}\n")

        logger.info(f"HAProxy WAF configuration generated at: {config_file}")

    except Exception as e:
        logger.error(f"Error generating HAProxy configuration: {e}")
        raise



def main() -> None:
    """Main function."""
    try:
        logger.info("Loading OWASP rules...")
        owasp_rules = load_owasp_rules(INPUT_FILE)
        logger.info(f"Loaded {len(owasp_rules)} rules.")

        logger.info("Generating HAProxy WAF configuration...")
        generate_haproxy_conf(owasp_rules)

        logger.info("HAProxy WAF generation complete.")

    except Exception as e:
        logger.critical(f"Script failed: {e}")
        exit(1)  # Exit with an error code


if __name__ == "__main__":
    main()
