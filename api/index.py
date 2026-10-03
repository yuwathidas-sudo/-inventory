import os, sys, re, html, hmac, hashlib, time, csv, io
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import store

SECRET = os.environ.get("SECRET", "dev-secret-change-me").encode()
STAFF = ("admin", "staff")
ALL = ("admin", "staff", "customer")
CSS = ("body{font-family:sans-serif;margin:0;background:#f4f6f8}nav{background:#0f6cbd;padding:10px;display:flex;gap:12px;flex-wrap:wrap}"
       "nav a,nav span{color:#fff;text-decoration:none}main{max-width:900px;margin:auto;padding:12px}"
       "input,select,button{padding:8px;margin:4px 0;width:100%;box-sizing:border-box}button{width:auto;cursor:pointer}"
       "table{border-collapse:collapse;width:100%;background:#fff;display:block;overflow-x:auto}td,th{border:1px solid #ddd;padding:6px;text-align:left}"
       ".msg{background:#e6f4ea;padding:8px}.err{background:#fde8e8;padding:8px;margin:4px 0}.card{display:inline-block;background:#fff;padding:12px;margin:4px;min-width:130px}"
       ".low{color:#b00020;font-weight:bold}form.inline{display:inline}")


def esc(s):
    return html.escape(str(s), quote=True)


class Resp(Exception):
    def __init__(self, code=200, body="", loc=None, cookie=None, ctype="text/html; charset=utf-8", fname=None):
        self.code, self.body, self.loc, self.cookie = code, body, loc, cookie
        self.ctype, self.fname = ctype, fname


def go(path, msg=""):
    return Resp(303, loc=path + ("?" + urlencode({"msg": msg}) if msg else ""))


# ---------- session ----------
def sig(msg):
    return hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()


def make_cookie(name):
    msg = "%s|%d" % (name, int(time.time()) + 86400)
    return msg + "|" + sig(msg)


def read_cookie(raw):
    for part in (raw or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "sid":
            try:
                name, exp, s = v.split("|")
                if hmac.compare_digest(s, sig(name + "|" + exp)) and int(exp) > time.time():
                    return name
            except ValueError:
                return None
    return None


# ---------- HTML ----------
def page(user, title, body, msg=""):
    nav = ""
    if user:
        links = [("/products", "สินค้า")]
        if user["role"] in STAFF:
            links = [("/dashboard", "แดชบอร์ด"), ("/products", "สินค้า"), ("/report", "รายงาน"), ("/suppliers", "ผู้ขาย"), ("/pos", "ใบสั่งซื้อ")]
        if user["role"] == "admin":
            links += [("/logs", "Log"), ("/users", "ผู้ใช้")]
        nav = "".join('<a href="%s">%s</a>' % l for l in links)
        nav += '<span>%s (%s)</span><a href="/logout">ออก</a>' % (esc(user["name"]), user["role"])
    flash = ('<p class="%s">%s</p>' % ("err" if msg.startswith("!") else "msg", esc(msg.lstrip("!")))) if msg else ""
    return ("<!doctype html><html lang=th><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><style>%s</style><nav>%s</nav><main>%s%s</main></html>") % (esc(title), CSS, nav, flash, body)


def errbox(errs):
    return "".join('<p class="err">%s</p>' % esc(e) for e in errs)


def need(user, *roles):
    if not user:
        raise Resp(303, loc="/login")
    if user["role"] not in roles:
        raise Resp(403, page(user, "ไม่มีสิทธิ์", "<h2>คุณไม่มีสิทธิ์เข้าถึงหน้านี้</h2>"))
    return user


def auth_page(kind, errs=(), name=""):
    t = "เข้าสู่ระบบ" if kind == "login" else "สมัครสมาชิก"
    other = '<a href="/register">สมัครสมาชิก</a>' if kind == "login" else '<a href="/login">มีบัญชีแล้ว</a>'
    return page(None, t, '<h2>%s</h2>%s<form method=post>ชื่อผู้ใช้<input name=username value="%s" required>'
                'รหัสผ่าน<input name=password type=password required><button>%s</button></form>%s'
                % (t, errbox(errs), esc(name), t, other))


FIELDS = [("sku", "รหัส SKU"), ("name", "ชื่อสินค้า"), ("category", "หมวด"), ("unit", "หน่วยนับ"),
          ("cost", "ราคาทุน"), ("price", "ราคาขาย"), ("reorder", "จุดสั่งซื้อ (reorder point)")]


def product_form(user, action, v, errs, creating):
    fields = FIELDS + ([("qty", "จำนวนเริ่มต้น")] if creating else [])
    inputs = "".join('<label>%s<input name="%s" value="%s"></label>' % (lb, k, esc(v.get(k, ""))) for k, lb in fields)
    return page(user, "สินค้า", "<h2>%s</h2>%s<form method=post action='%s'>%s<button>บันทึก</button></form>"
                % ("เพิ่มสินค้า" if creating else "แก้ไขสินค้า", errbox(errs), action, inputs))


def status_of(p):
    if p["qty"] == 0:
        return '<span class="low">หมด</span>'
    return '<span class="low">ใกล้หมด</span>' if p["qty"] <= p["reorder"] else "ปกติ"


def table(head, rows):
    return "<table><tr>%s</tr>%s</table>" % ("".join("<th>%s</th>" % h for h in head),
                                              "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in r) for r in rows))


def options(items, label):
    return "".join('<option value="%s">%s</option>' % (i, esc(label(x))) for i, x in items)


def post_btn(action, text, confirm=""):
    c = ' onclick="return confirm(\'%s\')"' % confirm if confirm else ""
    return '<form class="inline" method=post action="%s"><button%s>%s</button></form>' % (action, c, text)


# ---------- routes ----------
def dispatch(m, path, q, form, db, user):
    msg = q.get("msg", "")
    uname = user["name"] if user else ""

    if path == "/":
        return go("/dashboard" if user and user["role"] in STAFF else "/products" if user else "/login")

    if path == "/login":
        if m == "POST":
            rec = db["users"].get(form.get("username", "").strip().lower())
            if rec and store.check_pw(form.get("password", ""), rec["pw"]):
                r = go("/")
                r.cookie = make_cookie(form["username"].strip().lower())
                return r
            return Resp(200, auth_page("login", ["ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"], form.get("username", "")))
        return Resp(200, auth_page("login"))

    if path == "/register":
        if m == "POST":
            err = store.register_user(db, form.get("username", ""), form.get("password", ""))
            if err:
                return Resp(200, auth_page("register", [err], form.get("username", "")))
            return go("/login", "สมัครสำเร็จ กรุณาเข้าสู่ระบบ")
        return Resp(200, auth_page("register"))

    if path == "/logout":
        r = go("/login")
        r.cookie = ""
        return r

    if path == "/dashboard":
        need(user, *STAFF)
        s = store.stats(db)
        cards = "".join('<div class="card">%s<br><b>%s</b></div>' % (a, b) for a, b in (
            ("จำนวน SKU", s["skus"]), ("ชิ้นรวม", s["units"]), ("มูลค่าสต็อก (ทุน)", "%.2f" % s["value"]),
            ("ใกล้หมด/หมด", len(s["low"]))))
        low = table(["SKU", "ชื่อ", "คงเหลือ", "จุดสั่งซื้อ"],
                    [[esc(p["sku"]), esc(p["name"]), p["qty"], p["reorder"]] for _, p in s["low"]]) if s["low"] else "<p>ไม่มีสินค้าใกล้หมด</p>"
        cat = table(["หมวด", "มูลค่า"], [[esc(k), "%.2f" % v] for k, v in sorted(s["by_cat"].items())])
        return Resp(200, page(user, "แดชบอร์ด", "<h2>แดชบอร์ด</h2>%s<h3>แจ้งเตือนต่ำกว่าจุดสั่งซื้อ</h3>%s<h3>มูลค่าสต็อกตามหมวด</h3>%s" % (cards, low, cat), msg))

    if path in ("/report", "/report.csv"):
        need(user, *STAFF)
        rows, total = store.report_rows(db)
        if path == "/report.csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["SKU", "ชื่อ", "หมวด", "หน่วย", "คงเหลือ", "ราคาทุน", "มูลค่า"])
            for r in rows:  # กัน CSV injection: ข้อความที่ขึ้นต้นด้วย = + - @
                w.writerow([("'" + c) if isinstance(c, str) and c and c[0] in "=+-@" else c for c in r])
            return Resp(200, "\ufeff" + buf.getvalue(), ctype="text/csv; charset=utf-8", fname="stock_report.csv")
        t = table(["SKU", "ชื่อ", "หมวด", "คงเหลือ", "ราคาทุน", "มูลค่า"],
                  [[esc(r[0]), esc(r[1]), esc(r[2]), "%d %s" % (r[4], esc(r[3])), "%.2f" % r[5], "%.2f" % r[6]] for r in rows]
                  + [["<b>รวม</b>", "", "", "", "", "<b>%.2f</b>" % total]])
        return Resp(200, page(user, "รายงาน", '<h2>รายงานสินค้าคงเหลือและมูลค่าสต็อก</h2><p><a href="/report.csv">ส่งออก CSV (เปิดใน Excel)</a></p>' + t, msg))

    if path == "/products":
        need(user, *ALL)
        try:
            pg = int(q.get("page", "1"))
        except ValueError:
            pg = 1
        rows, pg, pages, total = store.query_products(db, q.get("q", ""), q.get("cat", ""), q.get("sort", "name"), q.get("desc") == "1", pg)
        cats = sorted({p["category"] for p in db["products"].values()})
        filt = ('<form method=get><input name=q placeholder="ค้นหา SKU/ชื่อ" value="%s"><select name=cat><option value="">ทุกหมวด</option>%s</select>'
                '<select name=sort>%s</select><label><input type=checkbox name=desc value=1 style="width:auto"> มาก→น้อย</label> <button>ค้นหา</button></form>'
                % (esc(q.get("q", "")), "".join('<option%s>%s</option>' % (" selected" if c == q.get("cat") else "", esc(c)) for c in cats),
                   "".join('<option value="%s">%s</option>' % kv for kv in (("name", "เรียงตามชื่อ"), ("sku", "SKU"), ("price", "ราคา"), ("qty", "คงเหลือ")))))
        staff = user["role"] in STAFF
        head = ["SKU", "ชื่อ", "หมวด", "ราคาขาย", "คงเหลือ", "สถานะ"] + (["ทุน", ""] if staff else [])
        out = []
        for i, p in rows:
            r = [esc(p["sku"]), esc(p["name"]), esc(p["category"]), "%.2f" % p["price"], "%d %s" % (p["qty"], esc(p["unit"])), status_of(p)]
            if staff:
                acts = '<a href="/products/%s">ดู/เบิกจ่าย</a> <a href="/products/%s/edit">แก้ไข</a>' % (i, i)
                if user["role"] == "admin":
                    acts += post_btn("/products/%s/delete" % i, "ลบ", "ลบสินค้านี้?")
                r += ["%.2f" % p["cost"], acts]
            out.append(r)
        base = {k: q[k] for k in ("q", "cat", "sort", "desc") if q.get(k)}
        pager = "".join('<a href="/products?%s"> [%d] </a>' % (urlencode({**base, "page": n}), n) if n != pg else " <b>[%d]</b> " % n for n in range(1, pages + 1))
        add = '<p><a href="/products/new">+ เพิ่มสินค้า</a></p>' if staff else ""
        return Resp(200, page(user, "สินค้า", "<h2>สินค้า (%d)</h2>%s%s%s<p>หน้า %s</p>" % (total, add, filt, table(head, out), pager), msg))

    if path == "/products/new":
        need(user, *STAFF)
        if m == "POST":
            c, errs = store.validate_product(db, form)
            if errs:
                return Resp(200, product_form(user, "/products/new", form, errs, True))
            store.add_product(db, uname, c)
            return go("/products", "เพิ่มสินค้าแล้ว")
        return Resp(200, product_form(user, "/products/new", {}, [], True))

    mt = re.fullmatch(r"/products/(\d+)(?:/(edit|delete|move))?", path)
    if mt:
        pid, act = mt.group(1), mt.group(2)
        need(user, *ALL if not act and m == "GET" else STAFF)
        p = db["products"].get(pid)
        if not p:
            return Resp(404, page(user, "ไม่พบ", "<h2>ไม่พบสินค้า</h2>"))
        if act == "delete":
            need(user, "admin")
            if m == "POST":
                store.delete_product(db, uname, pid)
                return go("/products", "ลบสินค้าแล้ว")
            return go("/products")
        if act == "move" and m == "POST":
            err = store.move_stock(db, uname, pid, form.get("kind", ""), form.get("qty", ""), form.get("reason", ""))
            return go("/products/" + pid, ("!" + err) if err else "บันทึกรายการแล้ว")
        if act == "edit":
            if m == "POST":
                c, errs = store.validate_product(db, form, pid, False)
                if errs:
                    return Resp(200, product_form(user, path, form, errs, False))
                store.update_product(db, uname, pid, c)
                return go("/products/" + pid, "แก้ไขแล้ว")
            return Resp(200, product_form(user, path, p, [], False))
        body = "<h2>%s</h2><p>SKU %s | หมวด %s | ราคาขาย %.2f | คงเหลือ %d %s | %s</p>" % (
            esc(p["name"]), esc(p["sku"]), esc(p["category"]), p["price"], p["qty"], esc(p["unit"]), status_of(p))
        if user["role"] in STAFF:
            ms = [m_ for m_ in reversed(db["moves"]) if m_["pid"] == pid][:50]
            body += ('<h3>รับเข้า / เบิกออก / ปรับยอด</h3><form method=post action="/products/%s/move"><select name=kind>'
                     '<option value=in>รับเข้า</option><option value=out>เบิกออก</option><option value=adjust>ปรับยอด (ใส่ยอดใหม่)</option></select>'
                     '<input name=qty placeholder="จำนวน"><input name=reason placeholder="เหตุผล"><button>บันทึก</button></form>'
                     '<h3>Stock card</h3>%s') % (pid, table(["เวลา", "ประเภท", "+/-", "คงเหลือ", "เหตุผล", "ผู้ทำ"],
                                                           [[x["ts"], x["kind"], "%+d" % x["delta"], x["after"], esc(x["reason"]), esc(x["user"])] for x in ms]))
        return Resp(200, page(user, p["name"], body, msg))

    if path == "/suppliers":
        need(user, *STAFF)
        err = ""
        if m == "POST":
            e = store.add_supplier(db, uname, form.get("name", ""), form.get("phone", ""))
            if not e:
                return go("/suppliers", "เพิ่มผู้ขายแล้ว")
            err = errbox([e])
        t = table(["ชื่อ", "โทร"], [[esc(s["name"]), esc(s["phone"])] for s in db["suppliers"].values()])
        return Resp(200, page(user, "ผู้ขาย", "<h2>ผู้ขาย</h2>%s%s<form method=post><input name=name placeholder='ชื่อผู้ขาย'>"
                              "<input name=phone placeholder='เบอร์โทร'><button>เพิ่ม</button></form>" % (err, t), msg))

    if path == "/pos":
        need(user, *STAFF)
        err = ""
        if m == "POST":
            e = store.create_po(db, uname, form.get("sid", ""), form.get("pid", ""), form.get("qty", ""))
            if not e:
                return go("/pos", "สร้างใบสั่งซื้อแล้ว")
            err = errbox([e])
        rows = []
        for i, po in sorted(db["pos"].items(), key=lambda x: -int(x[0])):
            sp, pr = db["suppliers"].get(po["sid"], {"name": "?"}), db["products"].get(po["pid"], {"sku": "?"})
            btn = post_btn("/pos/%s/receive" % i, "รับของเข้าคลัง") if po["status"] == "pending" else "รับแล้ว"
            rows.append(["PO#" + i, esc(sp["name"]), esc(pr["sku"]), po["qty"], po["ts"], btn])
        form_html = ("<form method=post><select name=sid>%s</select><select name=pid>%s</select><input name=qty placeholder='จำนวน'><button>สร้าง PO</button></form>"
                     % (options(db["suppliers"].items(), lambda s: s["name"]), options(db["products"].items(), lambda p: p["sku"] + " " + p["name"])))
        return Resp(200, page(user, "ใบสั่งซื้อ", "<h2>ใบสั่งซื้อ (PO)</h2>%s%s%s" % (err, form_html, table(["เลขที่", "ผู้ขาย", "สินค้า", "จำนวน", "เวลา", ""], rows)), msg))

    mt = re.fullmatch(r"/pos/(\d+)/receive", path)
    if mt and m == "POST":
        need(user, *STAFF)
        err = store.receive_po(db, uname, mt.group(1))
        return go("/pos", ("!" + err) if err else "รับของเข้าคลังแล้ว")

    if path == "/logs":
        need(user, "admin")
        rows = [[x["ts"], esc(x["user"]), esc(x["action"]), esc(x["detail"])] for x in reversed(db["logs"][-100:])]
        return Resp(200, page(user, "Log", "<h2>Log การแก้ไขข้อมูล (100 ล่าสุด)</h2>" + table(["เวลา", "ผู้ใช้", "การกระทำ", "รายละเอียด"], rows)))

    if path == "/users":
        need(user, "admin")
        if m == "POST":
            target, role = form.get("username", ""), form.get("role", "")
            if target not in db["users"] or role not in store.ROLES:
                return go("/users", "!ข้อมูลไม่ถูกต้อง")
            if target == uname:
                return go("/users", "!ไม่สามารถเปลี่ยนสิทธิ์ของตัวเองได้")
            db["users"][target]["role"] = role
            store.log(db, uname, "role_change", "%s → %s" % (target, role))
            return go("/users", "เปลี่ยนสิทธิ์แล้ว")
        rows = []
        for n, u in sorted(db["users"].items()):
            sel = "".join('<option%s>%s</option>' % (" selected" if r == u["role"] else "", r) for r in store.ROLES)
            rows.append([esc(n), '<form class="inline" method=post><input type=hidden name=username value="%s"><select name=role style="width:auto">%s</select><button>บันทึก</button></form>' % (esc(n), sel)])
        return Resp(200, page(user, "ผู้ใช้", "<h2>ผู้ใช้</h2>" + table(["ชื่อ", "สิทธิ์"], rows), msg))

    return Resp(404, page(user, "ไม่พบหน้า", "<h2>ไม่พบหน้านี้</h2>", ""))


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_req("GET")

    def do_POST(self):
        self.handle_req("POST")

    def handle_req(self, m):
        try:
            u = urlparse(self.path)
            path = u.path.rstrip("/") or "/"
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            form = {}
            if m == "POST":
                try:
                    n = min(int(self.headers.get("Content-Length", 0)), 100000)
                except ValueError:
                    n = 0
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode("utf-8", "replace"), keep_blank_values=True).items()}
            name = read_cookie(self.headers.get("Cookie"))
            try:
                with store.txn() as db:
                    user = {"name": name, "role": db["users"][name]["role"]} if name in db["users"] else None
                    r = dispatch(m, path, q, form, db, user)
            except Resp as e:
                r = e
        except Exception:  # ห้ามแสดง Traceback ให้ผู้ใช้
            r = Resp(500, page(None, "ผิดพลาด", "<h2>ระบบขัดข้องชั่วคราว กรุณาลองใหม่อีกครั้ง</h2><a href='/'>กลับหน้าแรก</a>"))
        self.send_response(r.code)
        if r.loc:
            self.send_header("Location", r.loc)
        if r.cookie is not None:
            self.send_header("Set-Cookie", "sid=%s; Path=/; HttpOnly; SameSite=Lax%s" % (r.cookie, "; Max-Age=0" if r.cookie == "" else ""))
        body = r.body.encode("utf-8")
        self.send_header("Content-Type", r.ctype)
        if r.fname:
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % r.fname)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print("เปิด http://localhost:8000")
    HTTPServer(("", 8000), handler).serve_forever()
