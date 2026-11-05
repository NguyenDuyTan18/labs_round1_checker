#!/usr/bin/env python3
"""Kiểm tra nhanh health và danh tính đội của Meko Boutique.

Ví dụ:
  python3 check.py http://10.90.0.11 --team team1

Công cụ này không đọc hay ghi flag. Flag đi qua chức năng thường của cửa hàng.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description="Meko Boutique health check")
    parser.add_argument("url")
    parser.add_argument("--team", required=True)
    args = parser.parse_args()
    try:
        with urllib.request.urlopen(args.url.rstrip("/") + "/health", timeout=5) as response:
            health = json.loads(response.read())
        if health.get("status") != "ok" or health.get("team") != args.team:
            raise RuntimeError("health/team mismatch")
        print(json.dumps({"health": "ok", "team": health["team"]}))
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        print(f"checker error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
