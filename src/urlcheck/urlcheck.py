"""Check URLs against Google Safe Browsing, test whether they still load, and draft a report email."""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import hyperlink
import iocextract
import requests
from PyFunceble import URLAvailabilityChecker
from pysafebrowsing import SafeBrowsing
from pysafebrowsing.api import SafeBrowsingException
from tqdm import tqdm

URLSCAN_API = "https://urlscan.io/api/v1/scan/"
URLSCAN_TIMEOUT = 30  # seconds


@dataclass
class Status:
    code: int | None
    reason: str
    alive: bool


@dataclass
class Result:
    url: str
    malicious: bool
    threats: list[str] = field(default_factory=list)
    status: Status | None = None
    urlscan: str | None = None


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    if args.file is None and sys.stdin.isatty():
        print("Reading URLs from stdin, press Ctrl-D to end.", file=sys.stderr)
    text = args.file.read_text() if args.file else sys.stdin.read()

    urls = sorted(set(extract_urls(text)))
    if not urls:
        raise SystemExit("No valid URLs found")

    results = lookup_gsb(urls, args.gsb_api_key)
    with ThreadPoolExecutor() as pool:
        futures = [pool.submit(check, result, args.urlscan_api_key) for result in results]
        progress = tqdm(
            as_completed(futures),
            total=len(futures),
            desc="Checking",
            unit=" URL",
            ncols=80,
            colour="yellow",
        )
        for future in progress:
            future.result()

    print(report(results))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="urlcheck",
        description="Checks URLs against Google Safe Browsing and checks their status",
    )
    parser.add_argument("-f", "--file", type=Path, help="Text containing URLs. Defaults to stdin")
    parser.add_argument(
        "-g",
        "--gsb_api_key",
        default=os.environ.get("GSB_API_KEY"),
        help="Defaults to GSB_API_KEY environment variable",
    )
    parser.add_argument(
        "-u",
        "--urlscan_api_key",
        default=os.environ.get("URLSCAN_API_KEY"),
        help="Defaults to URLSCAN_API_KEY environment variable. Scans are submitted as public",
    )
    args = parser.parse_args(argv)

    if not args.gsb_api_key:
        parser.error("a Google Safe Browsing key is required: pass -g or set GSB_API_KEY")
    if args.file and not args.file.is_file():
        parser.error(f"no such file: {args.file}")
    if not args.urlscan_api_key:
        print("Warning: URLSCAN_API_KEY is not set, skipping urlscan.io", file=sys.stderr)
    return args


def extract_urls(text: str) -> Iterator[str]:
    """Yield every URL in the text, refanged and normalized."""
    for raw in iocextract.extract_urls(text, refang=True):
        try:
            yield hyperlink.parse(raw).normalize().to_text()
        except ValueError:  # hyperlink.URLParseError; iocextract matches loosely
            continue


def lookup_gsb(urls: list[str], api_key: str) -> list[Result]:
    # shortcut: pysafebrowsing sets no request timeout, so a stalled GSB call hangs; replace the library if that bites.
    try:
        found = SafeBrowsing(api_key).lookup_urls(urls)
    except (SafeBrowsingException, requests.RequestException) as exc:
        raise SystemExit(f"Google Safe Browsing lookup failed: {exc!r}") from exc
    return [Result(url, v["malicious"], sorted(v.get("threats", []))) for url, v in found.items()]


def check(result: Result, urlscan_api_key: str | None) -> None:
    """Fill in the status and urlscan link. Never raises, so one bad URL cannot lose the run."""
    try:
        result.status = get_url_status(result.url)
    except Exception as exc:
        # Unknown counts as alive, so a flagged URL still gets a removal request.
        result.status = Status(None, f"check failed: {exc}", alive=True)
    if urlscan_api_key:
        result.urlscan = submit_urlscan(result.url, urlscan_api_key)


def get_url_status(url: str) -> Status:
    """Use PyFunceble to check whether the URL still loads."""
    # A checker keeps its subject and result on the instance, so threads must not share one.
    checker = URLAvailabilityChecker(
        use_extra_rules=True,
        use_whois_lookup=True,
        use_dns_lookup=True,
        use_netinfo_lookup=True,
        use_http_code_lookup=True,
        use_reputation_lookup=True,
        do_syntax_check_first=True,
        use_whois_db=True,
    )
    checker.set_subject(url)
    status = checker.get_status()
    code = status.http_status_code  # None when PyFunceble got no HTTP answer, e.g. bad syntax
    alive = code < 400 if code is not None else status.status == "ACTIVE"
    return Status(code, f"{status.status} ({status.status_source})", alive)


def submit_urlscan(url: str, api_key: str) -> str | None:
    """Submit a public scan at urlscan.io and return its result page, or None if it failed."""
    try:
        response = requests.post(
            URLSCAN_API,
            headers={"API-Key": api_key},
            json={"url": url, "visibility": "public"},
            timeout=URLSCAN_TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("result")
    except (requests.RequestException, ValueError) as exc:
        tqdm.write(f"Warning: urlscan.io failed for {url}: {exc}", file=sys.stderr)
        return None


def recommendation(result: Result) -> str:
    if not result.malicious:
        return "None.  OK"
    if result.status is None or result.status.alive:
        return f"Remove content from {urlsplit(result.url).path or '/'}"
    return "Request a review from Google."


def report(results: Iterable[Result]) -> str:
    """Return the email text for the site owner."""
    sections = []
    needs_removal = False
    for result in results:
        action = recommendation(result)
        needs_removal |= action.startswith("Remove")
        parts = urlsplit(result.url)
        lines = [
            f"\n# {obfuscate(result.url)}",
            f"+ {'Required Action:':>18} {action}",
            f"- {'Malicious:':>18} {result.malicious}",
        ]
        if result.threats:
            lines.append(f"- {'Threats:':>18} {', '.join(result.threats)}")
        if result.status:
            lines.append(
                f"- {'Status:':>18} {result.status.code or 'n/a'} - {result.status.reason}"
            )
        lines += [
            f"- {'Website:':>18} {parts.netloc}",
            f"- {'Path:':>18} {parts.path}",
            f"- {'Google Status:':>18} https://transparencyreport.google.com/safe-browsing/search?url={parts.netloc}",
        ]
        if result.urlscan:
            lines.append(f"- {'URLScan:':>18} {result.urlscan}")
        sections.append("\n".join(lines))

    intro = ["Hello,\n"]
    if not needs_removal:
        intro.append(
            "Thank you.  This case has been closed for now since none of the URLs appear to "
            "be serving flagged content any longer.  If more reports come in, however, this "
            "case will be reopened and you will be notified.\n"
        )
    intro.append(
        "Below is a summary of the URLs related to this issue including any required "
        "actions that remain to be taken."
    )
    outro = "\nIf you have any questions related to this issue please respond as soon as possible.\n\nRegards,\n"
    return "\n".join([*intro, *sections, outro])


def obfuscate(url: str) -> str:
    """Defang a URL so mail clients do not turn it into a link."""
    return re.sub(r"^http", "hxxp", url).replace(".", "[.]")


if __name__ == "__main__":
    main()
