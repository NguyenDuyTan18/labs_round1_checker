"""Meko Boutique — mô phỏng website thương mại thời trang và 5 lỗ hổng đào tạo có kiểm soát.

Mỗi đội chạy một tiến trình riêng với TEAM_ID và thư mục dữ liệu riêng. App không tự sinh hay đổi
flag: hệ thống chấm nạp flag qua chức năng thường của cửa hàng, mỗi flag là một bản ghi riêng và
chỉ lộ ra khi khai thác đúng lỗ hổng tương ứng.
"""
import base64
import functools
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from flask import (Flask, abort, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# Năm nhóm lỗ hổng phục vụ đào tạo.
TASKS = ("sqli", "idor", "upload", "jwt", "backup")
ROOT = Path(__file__).resolve().parent

# Hạng thành viên hợp lệ khi mua sắm. "c-nocturne" là hạng mời riêng, không cấp tự động
# qua giao diện — đây là trọng tâm của thử thách JWT.
PUBLIC_RANKS = {
    "basic": "Thành viên",
    "silver": "Bạc",
    "gold": "Vàng",
}
VIP_RANK = "c-nocturne"


def connect(path):
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def create_app(config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        DATA_DIR=Path(os.getenv("MEKO_DATA", "/var/lib/meko-boutique")),
        TEAM_ID=os.getenv("TEAM_ID", "team1"),
        STAFF_PASSWORD=os.getenv("MEKO_STAFF_PASSWORD", ""),
        MAX_CONTENT_LENGTH=256 * 1024,
    )
    app.config.update(config or {})
    data = Path(app.config["DATA_DIR"])
    data.mkdir(parents=True, exist_ok=True)
    app.config["DATA_DIR"] = data

    state_file = data / "state.json"
    app.config["STATE_FILE"] = state_file
    if not state_file.exists():
        state_file.write_text(json.dumps({
            "team": app.config["TEAM_ID"],
            "secret": secrets.token_hex(32),
            "jwt_secret": secrets.token_hex(32),
        }), encoding="utf-8")
        try:
            state_file.chmod(0o600)
        except OSError:
            pass
    state = json.loads(state_file.read_text(encoding="utf-8"))
    if state["team"] != app.config["TEAM_ID"]:
        raise ValueError("DATA_DIR đã thuộc đội khác; hãy dùng vùng dữ liệu riêng cho mỗi đội")

    app.secret_key = state["secret"]

    patches_path = data / "patches.json"
    patches = json.loads(patches_path.read_text(encoding="utf-8")) if patches_path.exists() else {}
    app.config["PATCHED"] = {t: bool(patches.get(t, False)) for t in TASKS}

    db_path = data / "shop.sqlite3"
    # Catalog tách khỏi shop.sqlite3: lỗi SQLi ở tìm bộ sưu tập chỉ chạm được dữ liệu của catalog,
    # không đọc được đơn hàng, ưu đãi VIP hay bản đối soát thuộc các thử thách khác.
    catalog_path = data / "catalog.sqlite3"
    seed = json.loads((ROOT / "data" / "seed.json").read_text(encoding="utf-8"))
    simulation = data / "simulation"
    designs = simulation / "designs"
    private_outfits = simulation / "private"
    designs.mkdir(parents=True, exist_ok=True)
    private_outfits.mkdir(parents=True, exist_ok=True)
    # Bản xem trước hợp lệ nằm trong vùng thiết kế công khai.
    (designs / "lookbook.txt").write_text(
        "Gợi ý phối: áo khoác linen cùng phụ kiện tông đất, giày lười trung tính.\n",
        encoding="utf-8")

    with connect(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, name TEXT, email TEXT, address TEXT, rank TEXT DEFAULT 'basic');
            CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, category TEXT, price INTEGER, image TEXT, description TEXT);
            CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, code TEXT, user_id INTEGER, total INTEGER, status TEXT, created TEXT, memo TEXT);
            CREATE TABLE IF NOT EXISTS order_items(order_id INTEGER, product_id INTEGER, quantity INTEGER, price INTEGER);
            CREATE TABLE IF NOT EXISTS outfits(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, manifest TEXT);
            CREATE TABLE IF NOT EXISTS saved_collection(user_id INTEGER, product_id INTEGER, PRIMARY KEY(user_id, product_id));
            CREATE TABLE IF NOT EXISTS coupons(code TEXT PRIMARY KEY, discount INTEGER, note TEXT);
            CREATE TABLE IF NOT EXISTS vip_offers(id INTEGER PRIMARY KEY, code TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reconciliation_notes(id INTEGER PRIMARY KEY, ref TEXT UNIQUE NOT NULL, value TEXT NOT NULL);
            """
        )
        if not db.execute("SELECT 1 FROM products LIMIT 1").fetchone():
            db.executemany("INSERT INTO products VALUES(?,?,?,?,?,?)",
                           [(p["id"], p["name"], p["category"], p["price"], p["image"], p["description"]) for p in seed["products"]])
            db.executemany("INSERT INTO coupons VALUES(?,?,?)",
                           [(c["code"], c["discount"], c["note"]) for c in seed["coupons"]])
            # Hồ sơ khách hàng giả lập và một đơn hàng mẫu để thí sinh thử hóa đơn của người khác.
            db.execute("INSERT INTO customers(id,username,password,name,email,address,rank) VALUES(900,?,?,?,?,?,?)",
                       ("khach-than-thiet", generate_password_hash(secrets.token_urlsafe()),
                        "An Nhiên", "annhien@example.test", "Hồ sơ giả lập · Đà Nẵng", "gold"))
            db.execute("INSERT INTO orders VALUES(9001,'DH-2026-09001',900,1290000,'Đang giao','04/11/2026',?)",
                       ("Giao trong giờ hành chính",))
            db.execute("INSERT INTO order_items VALUES(9001,2,1,1290000)")

    with connect(catalog_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS collections(id INTEGER PRIMARY KEY, title TEXT, description TEXT, season TEXT);
            CREATE TABLE IF NOT EXISTS collection_notes(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, collection_id INTEGER NOT NULL, note TEXT NOT NULL);
            """
        )
        if not db.execute("SELECT 1 FROM collections LIMIT 1").fetchone():
            db.executemany("INSERT INTO collections VALUES(?,?,?,?)",
                           [(c["id"], c["title"], c["description"], c["season"]) for c in seed["collections"]])

    def patched(task):
        return app.config["PATCHED"].get(task, False)

    def current_user(db):
        if not session.get("uid"):
            return None
        return db.execute("SELECT * FROM customers WHERE id=?", (session["uid"],)).fetchone()

    def user_required(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("uid"):
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapped

    def staff_required(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if session.get("staff") is not True:
                return redirect(url_for("staff_login"))
            return fn(*args, **kwargs)
        return wrapped

    def page(title, **kwargs):
        with connect(db_path) as db:
            products = db.execute("SELECT * FROM products ORDER BY id").fetchall()
        return render_template("shop.html", title=title, products=products,
                               customer=session.get("name"),
                               ranks=PUBLIC_RANKS | {VIP_RANK: "C-Nocturne"}, year=2026, **kwargs)

    def _cart_items(cart):
        with connect(db_path) as db:
            result = []
            for pid, qty in cart.items():
                p = db.execute("SELECT * FROM products WHERE id=?", (int(pid),)).fetchone()
                if p:
                    result.append(dict(p) | {"quantity": qty})
            return result

    @app.after_request
    def harden(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    # ---- Trang mua sắm công khai ----
    @app.get("/health")
    def health():
        with connect(db_path) as db:
            db.execute("SELECT 1").fetchone()
        return {"status": "ok", "service": "meko-boutique", "team": app.config["TEAM_ID"]}

    @app.get("/")
    def home():
        return page("Trang chủ", hero=True)

    @app.get("/category/<category>")
    def category(category):
        return page(category, category=category)

    @app.get("/search")
    def search():
        return page("Tìm kiếm", q=request.args.get("q", ""))

    @app.get("/product/<int:product_id>")
    def product(product_id):
        with connect(db_path) as db:
            item = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if not item:
            abort(404)
        return page(item["name"], item=item)

    @app.get("/collections")
    def collections():
        with connect(catalog_path) as db:
            rows = db.execute("SELECT * FROM collections ORDER BY id").fetchall()
        return page("Bộ sưu tập", collections=rows)

    @app.get("/collections/search")
    def collection_search():
        # === Thử thách SQL Injection (giới hạn trong catalog bộ sưu tập) ===
        # Nhân viên marketing lọc bộ sưu tập theo tên. Truy vấn nối chuỗi trực tiếp,
        # cho phép UNION sang bảng ghi chú riêng collection_notes trong cùng catalog.
        q = request.args.get("q", "")[:160]
        with connect(catalog_path) as db:
            if patched("sqli"):
                sql = "SELECT id,title,description FROM collections WHERE title LIKE ?"
                rows = db.execute(sql, ("%" + q + "%",)).fetchall()
            else:
                sql = "SELECT id,title,description FROM collections WHERE title LIKE '%" + q + "%'"
                rows = db.execute(sql).fetchall()
        return page("Tìm bộ sưu tập", collections=rows, q=q, searched=True)

    @app.route("/account/notes", methods=["GET", "POST"])
    @user_required
    def collection_notes():
        with connect(catalog_path) as db:
            if request.method == "POST":
                note = request.form.get("note", "").strip()
                collection_id = request.form.get("collection_id", type=int)
                if (not note or len(note) > 500 or not db.execute(
                        "SELECT 1 FROM collections WHERE id=?", (collection_id,)).fetchone()):
                    abort(400)
                cur = db.execute("INSERT INTO collection_notes(user_id,collection_id,note) VALUES(?,?,?)",
                                 (session["uid"], collection_id, note))
                return redirect(url_for("collection_note", note_id=cur.lastrowid))
            rows = db.execute(
                "SELECT n.id,c.title FROM collection_notes n JOIN collections c ON c.id=n.collection_id "
                "WHERE n.user_id=? ORDER BY n.id DESC", (session["uid"],)).fetchall()
            options = db.execute("SELECT id,title FROM collections ORDER BY id").fetchall()
        return page("Ghi chú bộ sưu tập", notes=rows, note_collections=options)

    @app.get("/account/notes/<int:note_id>")
    @user_required
    def collection_note(note_id):
        with connect(catalog_path) as db:
            note = db.execute(
                "SELECT n.*,c.title FROM collection_notes n JOIN collections c ON c.id=n.collection_id "
                "WHERE n.id=?", (note_id,)).fetchone()
        if not note:
            abort(404)
        if note["user_id"] != session["uid"]:
            abort(403)
        return page("Ghi chú bộ sưu tập", note=note)

    # ---- Tài khoản khách hàng ----
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return page("Tạo tài khoản", form="register")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[a-zA-Z0-9_-]{3,32}", username) or len(password) < 10:
            return page("Tạo tài khoản", form="register",
                        error="Tên tài khoản từ 3–32 ký tự (chữ, số, _ hoặc -); mật khẩu tối thiểu 10 ký tự."), 400
        try:
            with connect(db_path) as db:
                db.execute("INSERT INTO customers(username,password,name,email,address,rank) VALUES(?,?,?,?,?, 'basic')",
                           (username, generate_password_hash(password),
                            request.form.get("name", username)[:80],
                            request.form.get("email", "")[:120], "Chưa cập nhật"))
        except sqlite3.IntegrityError:
            return page("Tạo tài khoản", form="register", error="Tên tài khoản đã được sử dụng."), 409
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return page("Đăng nhập", form="login")
        with connect(db_path) as db:
            user = db.execute("SELECT * FROM customers WHERE username=?",
                              (request.form.get("username", ""),)).fetchone()
        if not user or not check_password_hash(user["password"], request.form.get("password", "")):
            return page("Đăng nhập", form="login", error="Thông tin đăng nhập chưa đúng."), 401
        session.clear()
        session["uid"] = user["id"]
        session["name"] = user["name"]
        # Cấp thẻ hội viên dạng JWT HS256. Hạng lấy từ hồ sơ khách; c-nocturne chỉ do nhân viên cấp.
        rank = user["rank"] if user["rank"] in PUBLIC_RANKS or user["rank"] == VIP_RANK else "basic"
        head = b64(b'{"alg":"HS256","typ":"JWT"}')
        body = b64(json.dumps({"sub": str(user["id"]), "rank": rank, "exp": int(time.time()) + 3600}).encode())
        signing = head + "." + body
        token = signing + "." + b64(hmac.digest(state["jwt_secret"].encode(), signing.encode(), "sha256"))
        response = redirect(request.args.get("next") or url_for("home"))
        response.set_cookie("meko_member", token, httponly=True, samesite="Lax")
        return response

    @app.post("/logout")
    def logout():
        session.clear()
        response = redirect(url_for("home"))
        response.delete_cookie("meko_member")
        return response

    @app.get("/account")
    @user_required
    def account():
        with connect(db_path) as db:
            user = current_user(db)
        return page("Tài khoản", form="account", profile=user)

    @app.post("/account/update")
    @user_required
    def update_account():
        with connect(db_path) as db:
            db.execute("UPDATE customers SET name=?,email=?,address=? WHERE id=?",
                       (request.form.get("name", "")[:80], request.form.get("email", "")[:120],
                        request.form.get("address", "")[:160], session["uid"]))
        session["name"] = request.form.get("name", "")[:80]
        return redirect(url_for("account"))

    @app.get("/account/collection")
    @user_required
    def personal_collection():
        with connect(db_path) as db:
            items = db.execute(
                "SELECT p.* FROM saved_collection s JOIN products p ON p.id=s.product_id WHERE s.user_id=? ORDER BY p.id",
                (session["uid"],)).fetchall()
        return page("Bộ sưu tập cá nhân", personal_items=items)

    @app.post("/account/collection/add/<int:product_id>")
    @user_required
    def save_product(product_id):
        with connect(db_path) as db:
            if not db.execute("SELECT 1 FROM products WHERE id=?", (product_id,)).fetchone():
                abort(404)
            db.execute("INSERT OR IGNORE INTO saved_collection VALUES(?,?)", (session["uid"], product_id))
        return redirect(url_for("personal_collection"))

    # ---- Giỏ hàng và đặt hàng ----
    @app.post("/cart/add/<int:product_id>")
    @user_required
    def cart_add(product_id):
        with connect(db_path) as db:
            item = db.execute("SELECT id FROM products WHERE id=?", (product_id,)).fetchone()
        if not item:
            abort(404)
        cart = session.get("cart", {})
        qty = max(1, min(5, int(request.form.get("quantity", 1) or 1)))
        cart[str(product_id)] = min(20, int(cart.get(str(product_id), 0)) + qty)
        session["cart"] = cart
        return redirect(url_for("cart"))

    @app.get("/cart")
    @user_required
    def cart():
        with connect(db_path) as db:
            coupons = db.execute("SELECT * FROM coupons ORDER BY discount").fetchall()
        return page("Giỏ hàng", cart_items=_cart_items(session.get("cart", {})), coupons=coupons)

    @app.post("/checkout")
    @user_required
    def checkout():
        items = _cart_items(session.get("cart", {}))
        if not items:
            return redirect(url_for("cart"))
        total = sum(x["price"] * x["quantity"] for x in items)
        coupon = request.form.get("coupon", "").upper()
        memo = request.form.get("memo", "").strip()[:160]
        with connect(db_path) as db:
            discount = db.execute("SELECT discount FROM coupons WHERE code=?", (coupon,)).fetchone()
            if discount:
                total = total * (100 - discount[0]) // 100
            code = "DH-" + str(secrets.randbelow(900000) + 100000)
            cur = db.execute(
                "INSERT INTO orders(code,user_id,total,status,created,memo) VALUES(?,?,?,'Đang xử lý','04/11/2026',?)",
                (code, session["uid"], total, memo))
            oid = cur.lastrowid
            db.executemany("INSERT INTO order_items VALUES(?,?,?,?)",
                           [(oid, x["id"], x["quantity"], x["price"]) for x in items])
        session["cart"] = {}
        return redirect(url_for("invoice", order_id=oid))

    @app.get("/account/orders")
    @user_required
    def orders():
        with connect(db_path) as db:
            rows = db.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (session["uid"],)).fetchall()
        return page("Đơn hàng của tôi", orders=rows)

    @app.get("/account/orders/<int:order_id>/invoice")
    @user_required
    def invoice(order_id):
        # === Thử thách IDOR (hóa đơn đơn hàng) ===
        # Hóa đơn tra theo id đơn đoán được. Khi chưa vá, không kiểm tra chủ sở hữu đơn.
        with connect(db_path) as db:
            order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
            if not order:
                abort(404)
            if patched("idor") and order["user_id"] != session["uid"]:
                abort(403)
            lines = db.execute(
                "SELECT p.name,oi.quantity,oi.price FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?",
                (order_id,)).fetchall()
        return page("Hóa đơn", invoice=order, invoice_items=lines)

    # ---- Studio phối đồ (upload) ----
    @app.route("/outfits/new", methods=["GET", "POST"])
    @user_required
    def outfit_new():
        if request.method == "GET":
            return page("Tạo bộ phối đồ", form="outfit")
        # === Thử thách Upload (manifest JSON của bộ phối) ===
        # Khách tải lên manifest JSON mô tả bộ phối; trường preview_file trỏ tới một tệp
        # bản xem trước. Khi chưa vá, đường dẫn không bị giới hạn trong designs, nhưng mọi
        # đường dẫn vẫn bị ép phải nằm dưới thư mục simulation — không bao giờ ra hệ thống host.
        upload = request.files.get("manifest")
        if not upload or not upload.filename or Path(upload.filename).suffix.lower() != ".json":
            abort(400)
        raw = upload.read(65537)
        if len(raw) > 65536:
            abort(413)
        try:
            manifest = json.loads(raw)
        except (ValueError, UnicodeError):
            abort(400)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("preview_file"), str):
            abort(400)
        note = manifest.pop("stylist_note", None)
        if note is not None and (not isinstance(note, str) or not 1 <= len(note) <= 500):
            abort(400)
        base = (data / "simulation" / "designs").resolve()
        sandbox_root = (data / "simulation").resolve()
        target = (base / manifest.get("preview_file", "")).resolve()
        if patched("upload") and not target.is_relative_to(base):
            abort(400)
        # Rào chắn cứng: dù vá hay chưa, không bao giờ cho đọc ra ngoài vùng simulation giả lập.
        if not target.is_relative_to(sandbox_root) or not target.is_file():
            abort(400)
        name = str(manifest.get("name", "Bộ phối mới"))[:80]
        # Ghi chú stylist là dữ liệu riêng: không lưu vào designs hay bản manifest công khai.
        public_manifest = json.dumps(manifest, ensure_ascii=False)
        with connect(db_path) as db:
            db.execute("INSERT INTO outfits(user_id,name,manifest) VALUES(?,?,?)",
                       (session["uid"], name, public_manifest))
        (base / (secrets.token_hex(12) + ".json")).write_text(public_manifest, encoding="utf-8")
        token = None
        if note is not None:
            token = secrets.token_hex(16)
            (private_outfits / (token + ".json")).write_text(
                json.dumps({"user_id": session["uid"], "name": name, "stylist_note": note}, ensure_ascii=False),
                encoding="utf-8")
        return page("Bản phối đã lưu", preview_text=target.read_text(encoding="utf-8"), outfit_token=token)

    @app.get("/outfits/<token>")
    @user_required
    def outfit_detail(token):
        path = private_outfits / (token + ".json")
        if not re.fullmatch(r"[0-9a-f]{32}", token) or not path.is_file():
            abort(404)
        outfit = json.loads(path.read_text(encoding="utf-8"))
        if outfit["user_id"] != session["uid"]:
            abort(403)
        return page(outfit["name"], outfit=outfit)

    # ---- Đặc quyền hội viên (JWT) ----
    def is_vip():
        # === Thử thách JWT (xác định hạng thành viên) ===
        # Hạng hội viên được đọc từ thẻ JWT trong cookie meko_member. Khi chưa vá, máy chủ
        # chấp nhận cả token alg=none (không chữ ký), cho phép giả mạo hạng c-nocturne.
        token = request.cookies.get("meko_member", "")
        member = {}
        try:
            head, body, sig = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
            claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            signing = head + "." + body
            expected = b64(hmac.digest(state["jwt_secret"].encode(), signing.encode(), "sha256"))
            valid = ((header.get("alg") == "none" and sig == "" and not patched("jwt"))
                     or (header.get("alg") == "HS256" and hmac.compare_digest(expected, sig)))
            if valid and claims.get("exp", 0) > time.time() and claims.get("sub") == str(session["uid"]):
                member = claims
        except (ValueError, TypeError, UnicodeError, AttributeError):
            pass
        return member.get("rank") in (VIP_RANK, VIP_RANK + "-plus")

    def vip_denied():
        return page("Đặc quyền hội viên", vip_locked=True,
                    error="Khu vực ưu đãi riêng dành cho hạng C-Nocturne."), 403

    @app.get("/member/benefits")
    @user_required
    def benefits():
        if not is_vip():
            return vip_denied()
        with connect(db_path) as db:
            offers = db.execute("SELECT id FROM vip_offers ORDER BY id DESC LIMIT 50").fetchall()
        return page("Đặc quyền C-Nocturne", vip_offers=offers)

    @app.get("/member/offers/<int:offer_id>")
    @user_required
    def member_offer(offer_id):
        if not is_vip():
            return vip_denied()
        with connect(db_path) as db:
            offer = db.execute("SELECT * FROM vip_offers WHERE id=?", (offer_id,)).fetchone()
        if not offer:
            abort(404)
        return page("Đặc quyền C-Nocturne", vip_offer=offer)

    # ---- Bản xuất dữ liệu vận hành (backup) ----
    @app.get("/exports/operations.sql")
    def operations_export():
        # === Thử thách Backup (bản xuất dữ liệu vận hành bị công khai) ===
        # Một bản đối soát vận hành bị để công khai qua HTTP (có gợi ý trong robots.txt).
        # Bản vá đúng là chỉ nhân viên mới tải được, không phải gỡ hẳn chức năng.
        if patched("backup") and session.get("staff") is not True:
            abort(404)
        with connect(db_path) as db:
            rows = db.execute("SELECT ref,value FROM reconciliation_notes ORDER BY id DESC LIMIT 100").fetchall()
        lines = ["-- Meko Boutique — ban xuat doi soat van hanh (du lieu gia lap)",
                 "-- Sinh tu quy trinh backup noi bo, khong danh cho khach hang."]
        for row in rows:
            ref, value = (row[key].replace("'", "''") for key in ("ref", "value"))
            lines.append("INSERT INTO reconciliation_notes(ref,value) VALUES ('" + ref + "','" + value + "');")
        return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.get("/robots.txt")
    def robots():
        lines = ["User-agent: *", "Disallow: /staff", "Disallow: /exports/"]
        return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    # ---- Khu vực nhân viên ----
    @app.route("/staff/login", methods=["GET", "POST"])
    def staff_login():
        if request.method == "GET":
            return page("Đăng nhập nhân viên", form="staff-login")
        if not app.config["STAFF_PASSWORD"] or not hmac.compare_digest(
                request.form.get("password", ""), app.config["STAFF_PASSWORD"]):
            return page("Đăng nhập nhân viên", form="staff-login", error="Không thể xác thực nhân viên."), 401
        session["staff"] = True
        return redirect(url_for("staff"))

    @app.get("/staff")
    @staff_required
    def staff():
        with connect(db_path) as db:
            all_orders = db.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
        return page("Vận hành cửa hàng", staff=True, orders=all_orders)

    @app.get("/staff/products")
    @staff_required
    def staff_products():
        with connect(db_path) as db:
            items = db.execute("SELECT * FROM products ORDER BY id").fetchall()
        return page("Quản lý sản phẩm", staff=True, staff_products=items)

    @app.post("/staff/products")
    @staff_required
    def staff_add_product():
        name = request.form.get("name", "").strip()[:100]
        price = request.form.get("price", type=int)
        cat = request.form.get("category", "").strip()[:60]
        if not name or not cat or not price or price < 1:
            abort(400)
        with connect(db_path) as db:
            db.execute("INSERT INTO products(name,category,price,image,description) VALUES(?,?,?,'bag.svg',?)",
                       (name, cat, price, request.form.get("description", "")[:240]))
        return redirect(url_for("staff_products"))

    @app.post("/staff/orders/<int:order_id>/status")
    @staff_required
    def staff_update_order(order_id):
        status = request.form.get("status", "")
        if status not in ("Đang xử lý", "Đang giao", "Đã giao", "Đã hủy"):
            abort(400)
        with connect(db_path) as db:
            db.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
        return redirect(url_for("staff"))

    @app.route("/staff/vip", methods=["GET", "POST"])
    @staff_required
    def staff_vip():
        with connect(db_path) as db:
            if request.method == "POST":
                code = request.form.get("code", "").strip()
                if not 1 <= len(code) <= 160:
                    abort(400)
                cur = db.execute("INSERT INTO vip_offers(code) VALUES(?)", (code,))
                return redirect(url_for("staff_vip_offer", offer_id=cur.lastrowid))
            offers = db.execute("SELECT id FROM vip_offers ORDER BY id DESC LIMIT 50").fetchall()
        return page("Ưu đãi C-Nocturne", staff=True, staff_offers=offers)

    @app.get("/staff/vip/offers/<int:offer_id>")
    @staff_required
    def staff_vip_offer(offer_id):
        with connect(db_path) as db:
            offer = db.execute("SELECT * FROM vip_offers WHERE id=?", (offer_id,)).fetchone()
        if not offer:
            abort(404)
        return page("Ưu đãi C-Nocturne", staff=True, staff_offers=[], staff_offer=offer)

    @app.post("/staff/vip/members")
    @staff_required
    def staff_vip_member():
        with connect(db_path) as db:
            changed = db.execute("UPDATE customers SET rank=? WHERE username=?",
                                 (VIP_RANK, request.form.get("username", ""))).rowcount
        if not changed:
            abort(404)
        return redirect(url_for("staff_vip"))

    @app.route("/staff/reconciliation", methods=["GET", "POST"])
    @staff_required
    def staff_reconciliation():
        with connect(db_path) as db:
            if request.method == "POST":
                value = request.form.get("value", "").strip()
                if not 1 <= len(value) <= 160:
                    abort(400)
                ref = "RC-" + secrets.token_hex(6)
                db.execute("INSERT INTO reconciliation_notes(ref,value) VALUES(?,?)", (ref, value))
                return redirect(url_for("staff_reconciliation", ref=ref))
            rows = db.execute("SELECT ref FROM reconciliation_notes ORDER BY id DESC LIMIT 100").fetchall()
        return page("Đối soát vận hành", staff=True, staff_reconciliations=rows)

    return app


if __name__ == "__main__":
    from waitress import serve
    serve(create_app(), host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8080")))
