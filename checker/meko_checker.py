"""Logic check/put/get của Meko Boutique cho ForcAD; chỉ dùng thư viện chuẩn.

Checker đi qua chức năng thường của cửa hàng như khách hàng và nhân viên, không dùng API riêng.
Checker không kiểm tra lỗ hổng còn tồn tại, nên đội vá đúng vẫn được UP.
"""
import html
import http.client
import http.cookiejar
import json
import random
import re
import secrets
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import (HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request,
                            build_opener)

UP, CORRUPT, MUMBLE, DOWN, CHECK_FAILED = 101, 102, 103, 104, 110
MAX_BODY = 1024 * 1024
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/17.6 Safari/605.1.15",
)


class Verdict(Exception):
    """Kết thúc action với một trạng thái ForcAD."""

    def __init__(self, status, public, private=""):
        super().__init__(public)
        self.status, self.public, self.private = status, public, private


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.location = headers.get("Location", "")
        self.text = body.decode("utf-8", "replace")


class Client:
    """Một phiên trình duyệt riêng, có cookie và không tự theo redirect."""

    def __init__(self, base, timeout):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.user_agent = random.choice(USER_AGENTS)
        self.opener = build_opener(ProxyHandler({}), NoRedirect(),
                                   HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, form=None, upload=None):
        headers = {"User-Agent": self.user_agent}
        data = None
        if upload is not None:
            boundary = "----meko" + secrets.token_hex(12)
            field, filename, content = upload
            data = (f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; '
                    f'filename="{filename}"\r\nContent-Type: application/json\r\n\r\n').encode()
            data += content + f"\r\n--{boundary}--\r\n".encode()
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
        elif form is not None:
            data = urlencode(form).encode()
        try:
            try:
                with self.opener.open(Request(self.base + path, data=data, headers=headers),
                                      timeout=self.timeout) as reply:
                    response = Response(reply.status, reply.headers, reply.read(MAX_BODY))
            except HTTPError as exc:
                with exc:
                    response = Response(exc.code, exc.headers, exc.read(MAX_BODY))
        except (URLError, OSError, http.client.HTTPException) as exc:
            raise Verdict(DOWN, "Service unreachable", type(exc).__name__) from exc
        if response.status in (502, 503, 504):
            raise Verdict(DOWN, "Service unavailable", f"HTTP {response.status} at {path}")
        return response


def expect(response, status, message):
    if response.status != status:
        raise Verdict(MUMBLE, message, f"HTTP {response.status}")
    return response


def location_match(response, pattern, message):
    target = urlsplit(response.location)
    found = re.fullmatch(pattern, target.path + ("?" + target.query if target.query else ""))
    if response.status != 302 or not found:
        raise Verdict(MUMBLE, message, f"HTTP {response.status}")
    return found.group(1)


def marker():
    return "meko-" + secrets.token_hex(10)


class Service:
    """Các bước dùng chung. Lớp con cài đặt check, put, get cho một loại dữ liệu."""

    def __init__(self, base, team=None, staff_password="", timeout=5):
        self.base, self.team = base, team
        self.staff_password, self.timeout = staff_password, timeout

    def client(self):
        return Client(self.base, self.timeout)

    def health(self):
        client = self.client()
        response = expect(client.request("/health"), 200, "Health failed")
        try:
            data = json.loads(response.text)
        except ValueError as exc:
            raise Verdict(MUMBLE, "Invalid health response") from exc
        if data.get("status") != "ok" or data.get("service") != "meko-boutique":
            raise Verdict(MUMBLE, "Unexpected service")
        if self.team and data.get("team") != self.team:
            raise Verdict(MUMBLE, "Wrong team identity")
        if "Meko Boutique" not in expect(client.request("/"), 200, "Home page failed").text:
            raise Verdict(MUMBLE, "Unexpected home page")

    def customer(self):
        """Đăng ký tài khoản mới, trả về phiên đã đăng nhập và thông tin đăng nhập."""
        client = self.client()
        username = "khach-" + secrets.token_hex(8)
        password = secrets.token_urlsafe(18)
        response = client.request("/register", {"username": username, "password": password,
                                                "name": "Khach " + secrets.token_hex(3),
                                                "email": username + "@example.test"})
        if response.status != 302:
            raise Verdict(MUMBLE, "Registration failed", f"HTTP {response.status}")
        self.sign_in(client, username, password, MUMBLE)
        return client, {"u": username, "p": password}

    @staticmethod
    def sign_in(client, username, password, failure):
        response = client.request("/login", {"username": username, "password": password})
        if response.status != 302:
            raise Verdict(failure, "Login failed", f"HTTP {response.status}")

    def owner(self, private):
        client = self.client()
        self.sign_in(client, private["u"], private["p"], CORRUPT)
        return client

    def staff(self):
        if not self.staff_password:
            raise Verdict(CHECK_FAILED, "Checker configuration invalid", "staff password missing")
        client = self.client()
        response = client.request("/staff/login", {"password": self.staff_password})
        if response.status != 302:
            raise Verdict(MUMBLE, "Staff login failed", f"HTTP {response.status}")
        return client

    @staticmethod
    def require_flag(response, flag):
        if response.status != 200 or flag not in response.text:
            raise Verdict(CORRUPT, "Flag missing", f"HTTP {response.status}")


class Idor(Service):
    """Ghi chú đơn hàng: chủ đơn đọc lại trên hóa đơn."""

    @staticmethod
    def order(client, memo):
        product = random.randint(1, 6)
        expect_redirect = client.request(f"/cart/add/{product}", {"quantity": "1"})
        if expect_redirect.status != 302:
            raise Verdict(MUMBLE, "Add to cart failed", f"HTTP {expect_redirect.status}")
        response = client.request("/checkout", {"memo": memo})
        return int(location_match(response, r"/account/orders/(\d+)/invoice", "Checkout failed"))

    def check(self):
        client, _ = self.customer()
        memo = marker()
        order_id = self.order(client, memo)
        invoice = expect(client.request(f"/account/orders/{order_id}/invoice"), 200, "Invoice failed")
        if memo not in invoice.text:
            raise Verdict(MUMBLE, "Order memo missing")
        orders = expect(client.request("/account/orders"), 200, "Order list failed")
        if f"/account/orders/{order_id}/invoice" not in orders.text:
            raise Verdict(MUMBLE, "Order missing from list")

    def put(self, flag):
        client, private = self.customer()
        order_id = self.order(client, flag)
        self.require_flag(client.request(f"/account/orders/{order_id}/invoice"), flag)
        return {"order_id": order_id}, private | {"id": order_id}

    def get(self, private, flag):
        client = self.owner(private)
        self.require_flag(client.request(f"/account/orders/{int(private['id'])}/invoice"), flag)


class Sqli(Service):
    """Ghi chú bộ sưu tập: chủ ghi chú đọc lại; tìm kiếm phải đúng kết quả."""

    @staticmethod
    def save_note(client, note):
        response = client.request("/account/notes", {"collection_id": "1", "note": note})
        return int(location_match(response, r"/account/notes/(\d+)", "Saving note failed"))

    def check(self):
        client, _ = self.customer()
        listing = expect(client.request("/collections"), 200, "Collections failed")
        titles = [html.unescape(title) for title in re.findall(r"<h2>([^<]+)</h2>", listing.text)]
        if not titles:
            raise Verdict(MUMBLE, "Collections empty")
        title = random.choice(titles)
        found = expect(client.request("/collections/search?" + urlencode({"q": title.split()[-1]})),
                       200, "Search failed")
        if title not in html.unescape(found.text):
            raise Verdict(MUMBLE, "Search result missing")
        empty = expect(client.request("/collections/search?" + urlencode({"q": marker()})),
                       200, "Search failed")
        if 'class="collection-card"' in empty.text:
            raise Verdict(MUMBLE, "Search filter broken")
        note = marker()
        note_id = self.save_note(client, note)
        if note not in expect(client.request(f"/account/notes/{note_id}"), 200, "Note failed").text:
            raise Verdict(MUMBLE, "Note missing")

    def put(self, flag):
        client, private = self.customer()
        note_id = self.save_note(client, flag)
        self.require_flag(client.request(f"/account/notes/{note_id}"), flag)
        return {"note_id": note_id}, private | {"id": note_id}

    def get(self, private, flag):
        client = self.owner(private)
        self.require_flag(client.request(f"/account/notes/{int(private['id'])}"), flag)


class Upload(Service):
    """Ghi chú stylist của bộ phối: preview hợp lệ phải chạy, chủ bộ phối đọc lại ghi chú."""

    @staticmethod
    def send(client, content):
        return client.request("/outfits/new", upload=("manifest", "outfit.json", content))

    def create(self, client, note):
        manifest = {"name": "Bo phoi " + secrets.token_hex(3), "preview_file": "lookbook.txt",
                    "stylist_note": note}
        response = expect(self.send(client, json.dumps(manifest).encode()), 200, "Upload failed")
        if "linen" not in response.text:
            raise Verdict(MUMBLE, "Preview missing")
        found = re.search(r'href="/outfits/([0-9a-f]{32})"', response.text)
        if not found:
            raise Verdict(MUMBLE, "Outfit link missing")
        return found.group(1)

    def check(self):
        client, _ = self.customer()
        note = marker()
        token = self.create(client, note)
        if note not in expect(client.request("/outfits/" + token), 200, "Outfit failed").text:
            raise Verdict(MUMBLE, "Stylist note missing")
        expect(self.send(client, b"not-json"), 400, "Invalid manifest accepted")

    def put(self, flag):
        client, private = self.customer()
        token = self.create(client, flag)
        self.require_flag(client.request("/outfits/" + token), flag)
        return {"token": token}, private | {"id": token}

    def get(self, private, flag):
        token = str(private["id"])
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            raise ValueError("invalid token")
        self.require_flag(self.owner(private).request("/outfits/" + token), flag)


class Jwt(Service):
    """Ưu đãi C-Nocturne: nhân viên tạo và cấp hạng, hội viên đọc bằng token hợp lệ."""

    def create(self, code):
        """Tạo ưu đãi, cấp hạng cho một khách mới, trả về phiên đã đăng nhập lại."""
        desk = self.staff()
        response = desk.request("/staff/vip", {"code": code})
        offer_id = int(location_match(response, r"/staff/vip/offers/(\d+)", "Creating offer failed"))
        client, private = self.customer()
        expect(client.request("/member/benefits"), 403, "Basic member reached VIP area")
        granted = desk.request("/staff/vip/members", {"username": private["u"]})
        if granted.status != 302:
            raise Verdict(MUMBLE, "Granting rank failed", f"HTTP {granted.status}")
        self.sign_in(client, private["u"], private["p"], MUMBLE)
        return client, private, offer_id

    def check(self):
        code = marker()
        client, _, offer_id = self.create(code)
        benefits = expect(client.request("/member/benefits"), 200, "VIP area failed")
        if f"/member/offers/{offer_id}" not in benefits.text:
            raise Verdict(MUMBLE, "Offer missing from list")
        if code not in expect(client.request(f"/member/offers/{offer_id}"), 200, "Offer failed").text:
            raise Verdict(MUMBLE, "Offer content missing")

    def put(self, flag):
        client, private, offer_id = self.create(flag)
        self.require_flag(client.request(f"/member/offers/{offer_id}"), flag)
        return {"offer_id": offer_id}, private | {"id": offer_id}

    def get(self, private, flag):
        client = self.owner(private)
        self.require_flag(client.request(f"/member/offers/{int(private['id'])}"), flag)


class Backup(Service):
    """Bản đối soát: nhân viên lưu và tải lại qua bản xuất vận hành."""

    @staticmethod
    def save(desk, value):
        response = desk.request("/staff/reconciliation", {"value": value})
        return location_match(response, r"/staff/reconciliation\?ref=(RC-[0-9a-f]+)",
                              "Saving reconciliation failed")

    def check(self):
        desk = self.staff()
        value = marker()
        ref = self.save(desk, value)
        export = expect(desk.request("/exports/operations.sql"), 200, "Export failed")
        if ref not in export.text or value not in export.text or "INSERT INTO" not in export.text:
            raise Verdict(MUMBLE, "Export content invalid")

    def put(self, flag):
        desk = self.staff()
        ref = self.save(desk, flag)
        self.require_flag(desk.request("/exports/operations.sql"), flag)
        return {"ref": ref}, {"id": ref}

    def get(self, private, flag):
        self.require_flag(self.staff().request("/exports/operations.sql"), flag)


SERVICES = {"idor": Idor, "sqli": Sqli, "upload": Upload, "jwt": Jwt, "backup": Backup}


def run(task, action, base, team=None, staff_password="", flag=None, private=None, timeout=5):
    """Chạy một action, luôn trả về {status, public, private}."""
    try:
        service = SERVICES[task](base, team, staff_password, timeout)
        if action == "check":
            service.health()
            service.check()
            return {"status": UP, "public": "OK", "private": ""}
        if action == "put":
            service.health()
            public, secret = service.put(flag)
            return {"status": UP, "public": json.dumps(public), "private": json.dumps(secret)}
        if action == "get":
            service.get(json.loads(private), flag)
            return {"status": UP, "public": "OK", "private": ""}
        raise ValueError("unknown action")
    except Verdict as verdict:
        return {"status": verdict.status, "public": verdict.public, "private": verdict.private}
    except (KeyError, TypeError, ValueError) as exc:
        return {"status": CHECK_FAILED, "public": "Checker failed", "private": type(exc).__name__}
