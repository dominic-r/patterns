import requests
import re
import json
from typing import List, Dict

OWASP_CRS_BASE_URL = "https://api.github.com/repos/coreruleset/coreruleset/contents/rules"
GITHUB_REF = "v4.0"

def fetch_rule_files() -> List[str]:
    # Step 1: Fetch all tags
    ref_url = "https://api.github.com/repos/coreruleset/coreruleset/git/refs/tags"
    ref_response = requests.get(ref_url)
    ref_response.raise_for_status()

    ref_data = ref_response.json()

    # Debugging: Print fetched refs to inspect
    available_refs = [ref['ref'] for ref in ref_data]
    print("Available refs:", available_refs)

    # Step 2: Find the closest matching tag
    matched_ref = next((ref for ref in available_refs if ref.endswith(f"{GITHUB_REF}.0")), None)

    if matched_ref:
        ref_sha = next(ref['object']['sha'] for ref in ref_data if ref['ref'] == matched_ref)
        print(f"[*] Found exact match for {GITHUB_REF}: {matched_ref}")
    else:
        # Fallback to latest tag
        latest_ref = ref_data[-1]
        ref_sha = latest_ref['object']['sha']
        print(f"[!] {GITHUB_REF} not found. Using latest: {latest_ref['ref']}")

    print(f"[*] Using ref SHA: {ref_sha}")

    # Step 3: Fetch rule files using the selected SHA
    rules_url = f"{OWASP_CRS_BASE_URL}?ref={ref_sha}"
    response = requests.get(rules_url)
    response.raise_for_status()

    files = [item['name'] for item in response.json() if item['name'].endswith('.conf')]
    return files

def fetch_owasp_rules(rule_files: List[str]) -> List[Dict[str, str]]:
    base_url = "https://raw.githubusercontent.com/coreruleset/coreruleset/v4.9.0/rules/"
    rules = []

    for file in rule_files:
        print(f"[*] Fetching {file}...")
        response = requests.get(base_url + file)
        response.raise_for_status()

        raw_text = response.text
        sec_rules = re.findall(r'SecRule.*?"(.*?)"', raw_text, re.DOTALL)

        for rule in sec_rules:
            pattern = rule.strip().replace("\\", "")
            category = file.split('-')[-1].replace('.conf', '')
            if pattern:
                rules.append({"category": category, "pattern": pattern})

    return rules

def save_as_json(rules: List[Dict[str, str]], output_file: str) -> None:
    with open(output_file, 'w') as f:
        json.dump(rules, f, indent=4)

if __name__ == "__main__":
    print("[*] Fetching available rule files from GitHub...")
    rule_files = fetch_rule_files()
    print(f"[*] Found {len(rule_files)} rule files.")

    rules = fetch_owasp_rules(rule_files)

    print(f"[*] {len(rules)} rules fetched.")
    save_as_json(rules, "owasp_rules.json")

    print("[*] Rules saved successfully.")
