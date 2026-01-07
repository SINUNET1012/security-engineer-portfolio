#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def _api(token: str, url: str, *, method: str = "GET") -> tuple[int, bytes]:
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bulk-repo-delete",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delete ALL repositories owned by a GitHub user (DANGEROUS).",
    )
    parser.add_argument(
        "--user",
        default="SINU1012",
        help="Owner login to delete (default: SINU1012).",
    )
    parser.add_argument(
        "--token-env",
        default="GH_TOKEN",
        help="Env var name that stores a GitHub PAT (default: GH_TOKEN).",
    )
    args = parser.parse_args()

    token = os.environ.get(args.token_env)
    if not token:
        print(
            f"Missing token: set env var {args.token_env} (classic PAT needs repo + delete_repo).",
            file=sys.stderr,
        )
        return 2

    repos: list[str] = []
    page = 1
    while True:
        qs = urllib.parse.urlencode({"per_page": 100, "page": page, "type": "owner"})
        status, body = _api(token, f"https://api.github.com/user/repos?{qs}")
        if status != 200:
            print(f"List failed: {status} {body.decode(errors='ignore')}", file=sys.stderr)
            return 1
        data = json.loads(body.decode())
        if not data:
            break
        for repo in data:
            owner = (repo.get("owner") or {}).get("login") or ""
            if owner.lower() == args.user.lower():
                repos.append(repo["full_name"])
        page += 1

    print("Repositories to delete:")
    for r in repos:
        print(f" - {r}")

    if not repos:
        print("Nothing to delete.")
        return 0

    confirm = input(
        f"\nThis will PERMANENTLY delete {len(repos)} repos owned by {args.user}.\n"
        "Type DELETE ALL to proceed: "
    ).strip()
    if confirm != "DELETE ALL":
        print("Canceled.")
        return 0

    for r in repos:
        status, body = _api(token, f"https://api.github.com/repos/{r}", method="DELETE")
        if status != 204:
            print(f"FAILED  {r}: {status} {body.decode(errors='ignore')}")
        else:
            print(f"DELETED {r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

