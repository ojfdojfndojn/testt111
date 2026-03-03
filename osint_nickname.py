#!/usr/bin/env python3
"""Simple OSINT nickname checker.

Checks whether a nickname appears to exist on a set of public profile URLs.
This tool uses only public web pages and does not bypass authentication.
"""

from __future__ import annotations

import argparse
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT = 8

SITE_PATTERNS: dict[str, str] = {
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Reddit": "https://www.reddit.com/user/{username}",
    "X": "https://x.com/{username}",
    "Instagram": "https://www.instagram.com/{username}/",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Twitch": "https://www.twitch.tv/{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Medium": "https://medium.com/@{username}",
    "DeviantArt": "https://www.deviantart.com/{username}",
}


@dataclass
class CheckResult:
    site: str
    url: str
    found: bool
    status: int | None
    note: str


class UsernameChecker:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, workers: int = 8):
        self.timeout = timeout
        self.workers = workers

    def _probe(self, site: str, pattern: str, username: str) -> CheckResult:
        encoded = quote(username, safe="._-")
        url = pattern.format(username=encoded)

        # Attempt HEAD first, then fallback to GET when needed.
        for method in ("HEAD", "GET"):
            req = Request(
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (compatible; NicknameOSINT/1.0; +https://example.local)"
                    )
                },
                method=method,
            )
            try:
                with urlopen(req, timeout=self.timeout) as response:
                    status = response.getcode()
                if status and 200 <= status < 300:
                    return CheckResult(site, url, True, status, "profile page reachable")
                if status == 404:
                    return CheckResult(site, url, False, status, "not found")
                return CheckResult(site, url, False, status, f"unexpected status {status}")
            except HTTPError as exc:
                if exc.code == 404:
                    return CheckResult(site, url, False, exc.code, "not found")
                # Some sites disallow HEAD (405). Retry with GET.
                if method == "HEAD" and exc.code in (400, 401, 403, 405):
                    continue
                return CheckResult(site, url, False, exc.code, f"http error: {exc.code}")
            except (URLError, socket.timeout) as exc:
                if method == "HEAD":
                    continue
                return CheckResult(site, url, False, None, f"network error: {exc}")

        return CheckResult(site, url, False, None, "unable to verify")

    def check(self, username: str, sites: Iterable[str] | None = None) -> list[CheckResult]:
        selected = dict(SITE_PATTERNS)
        if sites:
            selected = {name: SITE_PATTERNS[name] for name in sites if name in SITE_PATTERNS}

        results: list[CheckResult] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [
                executor.submit(self._probe, site, pattern, username)
                for site, pattern in selected.items()
            ]
            for future in as_completed(futures):
                results.append(future.result())

        return sorted(results, key=lambda item: item.site.lower())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "OSINT nickname lookup for public profiles. "
            "Use responsibly and only where legal."
        )
    )
    parser.add_argument("username", help="Nickname/username to search")
    parser.add_argument(
        "--site",
        action="append",
        choices=sorted(SITE_PATTERNS.keys()),
        help="Check only selected site(s). Can be passed multiple times.",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent workers")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    return parser.parse_args()


def print_table(results: list[CheckResult]) -> None:
    print(f"{'Site':14} {'Found':7} {'Status':6} URL")
    print("-" * 80)
    for r in results:
        status = "-" if r.status is None else str(r.status)
        found = "yes" if r.found else "no"
        print(f"{r.site:14} {found:7} {status:6} {r.url}")


def main() -> int:
    args = parse_args()
    checker = UsernameChecker(timeout=args.timeout, workers=args.workers)
    results = checker.check(args.username, sites=args.site)

    if args.json:
        print(json.dumps([asdict(r) for r in results], ensure_ascii=False, indent=2))
    else:
        print_table(results)

    found_count = sum(1 for item in results if item.found)
    print(f"\nFound on {found_count}/{len(results)} sites")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
