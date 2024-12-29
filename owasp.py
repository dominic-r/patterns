import requests
import re
import json
import logging
import os
import time
import base64
import hashlib
from typing import List, Dict, Optional

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# GitHub Configuration
GITHUB_REPO_URL = "https://api.github.com/repos/coreruleset/coreruleset"
OWASP_CRS_BASE_URL = f"{GITHUB_REPO_URL}/contents/rules"
GITHUB_REF = "v4"  # Target latest v4.x version (adjust as needed)

# Rate Limit and Retry Configuration
RATE_LIMIT_DELAY = 600  # Default delay in seconds if rate limit headers are missing (10 mins)
RETRY_DELAY = 5         # Base retry delay in seconds
MAX_RETRIES = 6         # Maximum number of retries
EXPONENTIAL_BACKOFF = True
BACKOFF_MULTIPLIER = 2

# GitHub Token (optional)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Read from environment variable


def fetch_with_retries(url: str) -> requests.Response:
    retries = 0
    headers = {}

    # Add token if available
    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
        logging.info("Using GitHub token for authenticated request.")

    while retries < MAX_RETRIES:
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                reset_time = int(response.headers['X-RateLimit-Reset'])
                wait_time = max(reset_time - int(time.time()), RATE_LIMIT_DELAY)
                logging.warning(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                wait_time = RETRY_DELAY * (BACKOFF_MULTIPLIER ** retries) if EXPONENTIAL_BACKOFF else RETRY_DELAY
                logging.warning(f"Retrying {url}... ({retries + 1}/{MAX_RETRIES}) in {wait_time} seconds.")
                time.sleep(wait_time)
                retries += 1
        except requests.RequestException as e:
            logging.error(f"Error fetching {url}: {e}")
            retries += 1
    raise requests.RequestException(f"Failed to fetch {url} after {MAX_RETRIES} retries.")


def fetch_latest_tag(ref_prefix: str) -> Optional[str]:
    logging.info("Fetching tags from GitHub...")
    ref_url = f"{GITHUB_REPO_URL}/git/refs/tags"
    try:
        ref_response = fetch_with_retries(ref_url)
        refs = ref_response.json()
        matching_refs = [ref['ref'] for ref in refs if ref['ref'].startswith(f"refs/tags/{ref_prefix}.")]
        matching_refs.sort(reverse=True, key=lambda x: x.split('.')[-1])
        if matching_refs:
            latest_tag = matching_refs[0]
            logging.info(f"Latest matching tag: {latest_tag}")
            return latest_tag
        logging.warning(f"No matching refs found for prefix {ref_prefix}. Falling back to latest tag.")
        return refs[-1]['ref']
    except Exception as e:
        logging.error(f"Failed to fetch tags. Reason: {e}")
        return None


def fetch_rule_files(ref: str) -> List[Dict[str, str]]:
    logging.info(f"Fetching rule files for ref {ref}...")
    rules_url = f"{OWASP_CRS_BASE_URL}?ref={ref.split('/')[-1]}"
    try:
        rules_response = fetch_with_retries(rules_url)
        files = [
            {"name": item['name'], "sha": item['sha']}
            for item in rules_response.json()
            if item['name'].endswith('.conf')
        ]
        logging.info(f"Found {len(files)} rule files.")
        return files
    except requests.RequestException as e:
        logging.error(f"Failed to fetch rule files from {rules_url}. Reason: {e}")
        return []


def fetch_github_blob(sha: str) -> str:
    blob_url = f"{GITHUB_REPO_URL}/git/blobs/{sha}"
    try:
        response = fetch_with_retries(blob_url)
        blob_data = response.json()
        return blob_data['content']
    except requests.RequestException as e:
        logging.error(f"Failed to fetch blob for SHA {sha}. Reason: {e}")
        return ""


def verify_blob_sha(file_sha: str, blob_content: str) -> bool:
    calculated_sha = hashlib.sha1(base64.b64decode(blob_content)).hexdigest()
    return calculated_sha == file_sha


def fetch_owasp_rules(rule_files: List[Dict[str, str]], ref: str) -> List[Dict[str, str]]:
    logging.info("Fetching OWASP rules...")
    rules = []

    for file in rule_files:
        logging.info(f"Fetching {file['name']}...")
        blob_content = fetch_github_blob(file['sha'])

        if not verify_blob_sha(file['sha'], blob_content):
            logging.warning(
                f"SHA mismatch for {file['name']}. Expected: {file['sha']}, "
                f"Calculated: {hashlib.sha1(base64.b64decode(blob_content)).hexdigest()}"
            )

        raw_text = base64.b64decode(blob_content).decode('utf-8')
        sec_rules = re.findall(r'SecRule\s+.*?"((?:[^"\\]|\\.)+?)"', raw_text, re.DOTALL)
        for rule in sec_rules:
            pattern = rule.strip().replace("\\", "")
            category = file['name'].split('-')[-1].replace('.conf', '')
            if pattern:
                rules.append({"category": category, "pattern": pattern})

    logging.info(f"{len(rules)} rules fetched.")
    return rules


def save_as_json(rules: List[Dict[str, str]], output_file: str) -> None:
    logging.info(f"Saving rules to {output_file}...")
    try:
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(rules, f, indent=4)
        logging.info(f"Rules saved successfully to {output_file}.")
    except IOError as e:
        logging.error(f"Failed to save rules to {output_file}. Reason: {e}")


if __name__ == "__main__":
    latest_ref = fetch_latest_tag(GITHUB_REF)
    if latest_ref:
        rule_files = fetch_rule_files(latest_ref)
        if rule_files:
            rules = fetch_owasp_rules(rule_files, latest_ref)
            if rules:
                save_as_json(rules, "owasp_rules.json")
            else:
                logging.error("Failed to fetch rules. Exiting.")
        else:
            logging.error("Failed to fetch rule files. Exiting.")
    else:
        logging.error("Failed to fetch tags. Exiting.")
