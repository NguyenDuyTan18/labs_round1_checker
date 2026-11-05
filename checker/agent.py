#!/usr/bin/env python3
"""Chạy trên VM checker: nhận một yêu cầu JSON qua stdin SSH, in kết quả JSON ra stdout."""
import argparse
import json
from pathlib import Path
import sys

from forcad import DEFAULT_CONFIG, execute
from meko_checker import CHECK_FAILED


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    args = parser.parse_args()
    try:
        request = json.loads(sys.stdin.read(16384))
        result = execute(json.loads(Path(args.config).read_text(encoding="utf-8")), request)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        result = {"status": CHECK_FAILED, "public": "Agent failed", "private": type(exc).__name__}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
