import os
import re
import time
import json
import base64
import hashlib
import logging
import requests
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

GITHUB_REPO_URL = "https://api.github.com/repos/coreruleset/coreruleset"
OWASP_CRS_BASE_URL = f"{GITHUB_REPO_URL}/contents/rules"
GITHUB_REF = "v4"
RATE_LIMIT_DELAY = 600
RETRY_DELAY = 5
MAX_RETRIES = 6
EXPONENTIAL_BACKOFF = True
BACKOFF_MULTIPLIER = 2
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


class GitHubRequestError(Exception):
    """Raised when fetching data from GitHub fails after all retries."""


def get_session() -> requests.Session:
    """
    Creates and returns a requests.Session with optional GitHub token auth.
    """
    session = requests.Session()
    if GITHUB_TOKEN:
        session.headers.update({"Authorization": f"token {GITHUB_TOKEN}"})
    return session


def fetch_with_retries(session: requests.Session, url: str) -> requests.Response:
    """
    Fetches the given URL with retries, handling rate limits and transient HTTP errors.
    Raises GitHubRequestError if the request cannot be completed after all retries.
    """
    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = session.get(url)
            if response.status_code == 403 and "X-RateLimit-Remaining" in response.headers:
                reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                wait_time = max(reset_time - int(time.time()), RATE_LIMIT_DELAY)
                logging.warning(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
                continue
            try:
                response.raise_for_status()
                return response
            except requests.HTTPError:
                # Handle non-200 codes that are not rate-limit related
                pass

            # Retry logic for other errors
            wait_time = (RETRY_DELAY * (BACKOFF_MULTIPLIER ** retries)
                         if EXPONENTIAL_BACKOFF else RETRY_DELAY)
            logging.warning(f"Retrying {url}... ({retries + 1}/{MAX_RETRIES}) in {wait_time} seconds.")
            time.sleep(wait_time)
            retries += 1
        except requests.RequestException as e:
            logging.error(f"Error fetching {url}: {e}")
            retries += 1

    raise GitHubRequestError(f"Failed to fetch {url} after {MAX_RETRIES} retries.")


def fetch_latest_tag(session: requests.Session, ref_prefix: str) -> Optional[str]:
    """
    Fetches the latest matching Git tag from the GitHub repository based on a version prefix.
    Falls back to the newest tag if no matching prefix is found. Returns the tag reference.
    """
    ref_url = f"{GITHUB_REPO_URL}/git/refs/tags"
    try:
        response = fetch_with_retries(session, ref_url)
        tags = response.json()
        if not tags:
            logging.warning("No tags found in the repository.")
            return None
        matching = [r["ref"] for r in tags if r["ref"].startswith(f"refs/tags/{ref_prefix}.")]
        matching.sort(reverse=True, key=lambda x: x.split(".")[-1])
        if matching:
            latest_tag = matching[0]
            logging.info(f"Latest matching tag: {latest_tag}")
            return latest_tag
        logging.warning(f"No matching refs found for prefix {ref_prefix}. Falling back to the latest tag.")
        return tags[-1]["ref"]
    except Exception as e:
        logging.error(f"Failed to fetch tags. Reason: {e}")
        return None


def fetch_rule_files(session: requests.Session, ref: str) -> List[Dict[str, str]]:
    """
    Fetches the list of rule files (.conf) from the given ref in the repository.
    Returns a list of dictionaries containing file name and SHA.
    """
    ref_name = ref.split("/")[-1] if "/" in ref else ref
    rules_url = f"{OWASP_CRS_BASE_URL}?ref={ref_name}"
    try:
        response = fetch_with_retries(session, rules_url)
        files = response.json()
        return [{"name": f["name"], "sha": f["sha"]} for f in files if f["name"].endswith(".conf")]
    except (GitHubRequestError, requests.RequestException) as e:
        logging.error(f"Failed to fetch rule files from {rules_url}. Reason: {e}")
        return []


def fetch_github_blob(session: requests.Session, sha: str) -> str:
    """
    Fetches the blob content (base64-encoded) for a given SHA from GitHub.
    Returns the content if successful, or an empty string on failure.
    """
    blob_url = f"{GITHUB_REPO_URL}/git/blobs/{sha}"
    try:
        response = fetch_with_retries(session, blob_url)
        return response.json().get("content", "")
    except (GitHubRequestError, requests.RequestException) as e:
        logging.error(f"Failed to fetch blob for SHA {sha}. Reason: {e}")
        return ""


def verify_blob_sha(file_sha: str, blob_content_b64: str) -> bool:
    """
    Verifies that the SHA of the decoded content matches the expected file_sha.
    """
    decoded_bytes = base64.b64decode(blob_content_b64)
    # Option 1: Verify Git’s actual blob SHA (header + content)
    blob_header = f"blob {len(decoded_bytes)}\0".encode("utf-8")
    calculated_sha = hashlib.sha1(blob_header + decoded_bytes).hexdigest()

    return calculated_sha == file_sha


def fetch_owasp_rules(session: requests.Session, rule_files: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Fetches the OWASP rule content for each rule file, extracts SecRule patterns,
    and returns a list of dicts with category and pattern.
    """
    rules = []
    for file in rule_files:
        logging.info(f"Fetching {file['name']}...")
        blob_b64 = fetch_github_blob(session, file["sha"])
        if not blob_b64:
            logging.warning(f"Skipping file {file['name']} due to empty blob content.")
            continue

        if not verify_blob_sha(file["sha"], blob_b64):
            decoded_bytes = base64.b64decode(blob_b64)
            calculated_sha = hashlib.sha1(decoded_bytes).hexdigest()
            logging.warning(
                f"SHA mismatch for {file['name']}. "
                f"Expected: {file['sha']}, Calculated: {calculated_sha}"
            )

        raw_text = base64.b64decode(blob_b64).decode("utf-8")
        sec_rules = re.findall(r'SecRule\s+.*?"((?:[^"\\]|\\.)+?)"', raw_text, re.DOTALL)
        category = file["name"].split("-")[-1].replace(".conf", "")
        for rule in sec_rules:
            pattern = rule.strip().replace("\\", "")
            if pattern:
                rules.append({"category": category, "pattern": pattern})

    logging.info(f"Fetched {len(rules)} rules.")
    return rules


def save_as_json(rules: List[Dict[str, str]], output_file: str) -> bool:
    """
    Saves the given list of rules to a JSON file. Returns True if successful, False otherwise.
    """
    try:
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=4)
        logging.info(f"Rules saved to {output_file}.")
        return True
    except IOError as e:
        logging.error(f"Failed to save rules to {output_file}. Reason: {e}")
        return False


if __name__ == "__main__":
    session = get_session()
    latest_ref = fetch_latest_tag(session, GITHUB_REF)
    if latest_ref:
        rule_files = fetch_rule_files(session, latest_ref)
        if rule_files:
            rules = fetch_owasp_rules(session, rule_files)
            if rules and save_as_json(rules, "owasp_rules.json"):
                logging.info("All rules fetched and saved successfully.")
            else:
                logging.error("Failed to fetch or save rules.")
        else:
            logging.error("Failed to fetch rule files.")
    else:
        logging.error("Failed to fetch tags.")
