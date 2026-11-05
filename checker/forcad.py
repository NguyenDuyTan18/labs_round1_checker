"""Giao thức dòng lệnh của ForcAD và đọc cấu hình đội.

  <script> check <ip>
  <script> put <ip> <flag_id> <flag> <vuln>
  <script> get <ip> <private_flag_data> <flag> <vuln>

stdout là thông điệp công khai, stderr là dữ liệu riêng, mã thoát là trạng thái.
"""
import json
import os
from pathlib import Path
import sys

from meko_checker import CHECK_FAILED, run

DEFAULT_CONFIG = "/etc/meko-checker/config.json"


def execute(config, request):
    """Chạy yêu cầu {task, action, ip, flag, locator} với cấu hình đã nạp."""
    team = config["teams"][request["ip"]]
    return run(request["task"], request["action"], team["url"], team=team.get("team"),
               staff_password=team.get("staff_password", ""), flag=request.get("flag"),
               private=request.get("locator"), timeout=float(config.get("timeout", 5)))


def main(task):
    try:
        action, ip = sys.argv[1:3]
        request = {"task": task, "action": action, "ip": ip}
        if action in ("put", "get"):
            if len(sys.argv) != 6:
                raise ValueError("invalid arguments")
            request.update(locator=sys.argv[3], flag=sys.argv[4])
        elif action != "check" or len(sys.argv) != 3:
            raise ValueError("invalid arguments")
        path = Path(os.environ.get("MEKO_CHECKER_CONFIG", DEFAULT_CONFIG))
        result = execute(json.loads(path.read_text(encoding="utf-8")), request)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        result = {"status": CHECK_FAILED, "public": "Checker failed", "private": type(exc).__name__}
    print(result["public"])
    print(result["private"], file=sys.stderr)
    return result["status"]
