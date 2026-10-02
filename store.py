"""ชั้นข้อมูลและ logic ทั้งหมด (Standard Library เท่านั้น)"""
import json, os, re, math, hmac, hashlib, secrets, threading
from contextlib import contextmanager
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
# Vercel เขียนไฟล์ได้เฉพาะ /tmp (ข้อมูลไม่ถาวร) / รันในเครื่องใช้ data.json
PATH = "/tmp/data.json" if os.environ.get("VERCEL") else os.path.join(BASE, "data.json")
LOCK = threading.Lock()
ROLES = ("admin", "staff", "customer")


# ---------- รหัสผ่าน ----------
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000).hex()
    return salt + "$" + h


def check_pw(pw, stored):
    return hmac.compare_digest(hash_pw(pw, stored.split("$")[0]), stored)


# ---------- ไฟล์ ----------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def new_db():
    db = {"users": {}, "products": {}, "moves": [], "suppliers": {},
          "pos": {}, "logs": [], "seq": 1}
    db["users"]["admin"] = {"pw": hash_pw("admin1234"), "role": "admin"}
    db["users"]["staff"] = {"pw": hash_pw("staff1234"), "role": "staff"}
    return db


def load():
    try:
        with open(PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return new_db()


def save(db):
    try:
        tmp = PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False)
        os.replace(tmp, PATH)
        return True
    except OSError:
        return False


@contextmanager
def txn():
    """โหลด -> แก้ -> บันทึก (บันทึกเมื่อไม่มี exception)"""
    with LOCK:
        db = load()
        yield db
        save(db)


def next_id(db):
    db["seq"] += 1
    return str(db["seq"] - 1)


def log(db, user, action, detail):
    db["logs"].append({"ts": now(), "user": user, "action": action, "detail": detail})


# ---------- ตรวจสอบข้อมูล ----------
def to_num(text, kind, label, minv=0, maxv=10 ** 9):
    try:
        v = kind(str(text).strip())
    except (ValueError, TypeError):
        return None, label + " ต้องเป็นตัวเลข" + ("จำนวนเต็ม" if kind is int else "")
    if kind is float and not math.isfinite(v):
        return None, label + " ไม่ถูกต้อง"
    if v < minv or v > maxv:
        return None, "%s ต้องอยู่ระหว่าง %s ถึง %s" % (label, minv, maxv)
    return v, None


def register_user(db, name, pw):
    name = name.strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{3,20}", name):
        return "ชื่อผู้ใช้ใช้ a-z 0-9 _ ยาว 3-20 ตัว"
    if len(pw) < 8 or len(pw) > 100:
        return "รหัสผ่านต้องยาว 8 ตัวขึ้นไป"
    if name in db["users"]:
        return "ชื่อผู้ใช้นี้ถูกใช้แล้ว"
    db["users"][name] = {"pw": hash_pw(pw), "role": "customer"}
    log(db, name, "register", "สมัครสมาชิก")
    return None


def validate_product(db, form, pid=None, creating=True):
    errs, c = [], {}
    sku = form.get("sku", "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9_-]{1,20}", sku):
        errs.append("SKU ใช้ A-Z 0-9 _ - ยาว 1-20 ตัว")
    elif any(p["sku"] == sku and i != pid for i, p in db["products"].items()):
        errs.append("SKU ซ้ำกับสินค้าอื่น")
    c["sku"] = sku
    for key, label, mx in (("name", "ชื่อสินค้า", 80), ("category", "หมวด", 30), ("unit", "หน่วยนับ", 15)):
        v = form.get(key, "").strip()
        if not v or len(v) > mx:
            errs.append("%s ต้องไม่ว่างและไม่เกิน %d ตัวอักษร" % (label, mx))
        c[key] = v
    for key, label, kind in (("cost", "ราคาทุน", float), ("price", "ราคาขาย", float), ("reorder", "จุดสั่งซื้อ", int)):
        v, e = to_num(form.get(key, ""), kind, label)
        if e:
            errs.append(e)
        c[key] = v
    if creating:
        v, e = to_num(form.get("qty", "") or "0", int, "จำนวนเริ่มต้น")
        if e:
            errs.append(e)
        c["qty"] = v
    return c, errs


# ---------- สินค้า / สต็อก ----------
def add_product(db, user, c):
    pid = next_id(db)
    db["products"][pid] = {k: c[k] for k in ("sku", "name", "category", "unit", "cost", "price", "reorder")}
    db["products"][pid]["qty"] = 0
    log(db, user, "product_create", "%s %s" % (c["sku"], c["name"]))
    if c["qty"] > 0:
        move_stock(db, user, pid, "in", str(c["qty"]), "ยอดยกมา")
    return pid


def update_product(db, user, pid, c):
    p = db["products"][pid]
    diffs = ["%s: %s→%s" % (k, p[k], c[k]) for k in c if k in p and p[k] != c[k]]
    p.update({k: c[k] for k in c if k in p and k != "qty"})
    log(db, user, "product_update", "%s %s" % (p["sku"], "; ".join(diffs) or "ไม่มีการเปลี่ยนแปลง"))


def delete_product(db, user, pid):
    p = db["products"].pop(pid, None)
    if p:
        log(db, user, "product_delete", "%s %s (คงเหลือ %s)" % (p["sku"], p["name"], p["qty"]))


def move_stock(db, user, pid, kind, qty_text, reason):
    """คืนข้อความ error หรือ None ถ้าสำเร็จ"""
    p = db["products"].get(pid)
    if not p:
        return "ไม่พบสินค้า"
    if kind not in ("in", "out", "adjust"):
        return "ประเภทรายการไม่ถูกต้อง"
    reason = reason.strip()
    if not reason or len(reason) > 100:
        return "กรุณาระบุเหตุผล (ไม่เกิน 100 ตัวอักษร)"
    n, e = to_num(qty_text, int, "จำนวน", 0 if kind == "adjust" else 1)
    if e:
        return e
    if kind == "in":
        delta = n
    elif kind == "out":
        if n > p["qty"]:
            return "เบิกเกินจำนวนคงเหลือ (มี %d)" % p["qty"]
        delta = -n
    else:
        delta = n - p["qty"]
    p["qty"] += delta
    db["moves"].append({"id": next_id(db), "pid": pid, "kind": kind, "delta": delta,
                        "after": p["qty"], "reason": reason, "user": user, "ts": now()})
    log(db, user, "stock_" + kind, "%s %+d คงเหลือ %d (%s)" % (p["sku"], delta, p["qty"], reason))
    return None


def query_products(db, q="", cat="", sort="name", desc=False, page=1, per=5):
    items = list(db["products"].items())
    q = q.strip().lower()
    if q:
        items = [x for x in items if q in x[1]["name"].lower() or q in x[1]["sku"].lower()]
    if cat:
        items = [x for x in items if x[1]["category"] == cat]
    key = sort if sort in ("name", "sku", "price", "qty") else "name"
    items.sort(key=lambda x: x[1][key] if key in ("price", "qty") else x[1][key].lower(), reverse=desc)
    pages = max(1, math.ceil(len(items) / per))
    page = min(max(page, 1), pages)
    return items[(page - 1) * per: page * per], page, pages, len(items)


def stats(db):
    ps = db["products"].values()
    by_cat = {}
    for p in ps:
        by_cat[p["category"]] = by_cat.get(p["category"], 0) + p["qty"] * p["cost"]
    low = [(i, p) for i, p in db["products"].items() if p["qty"] <= p["reorder"]]
    return {"skus": len(db["products"]), "units": sum(p["qty"] for p in ps),
            "value": sum(p["qty"] * p["cost"] for p in ps), "low": low, "by_cat": by_cat}


# ---------- ผู้ขาย / ใบสั่งซื้อ ----------
def add_supplier(db, user, name, phone):
    name, phone = name.strip(), phone.strip()
    if not name or len(name) > 60:
        return "ชื่อผู้ขายต้องไม่ว่างและไม่เกิน 60 ตัวอักษร"
    if not re.fullmatch(r"[0-9+\- ]{8,15}", phone):
        return "เบอร์โทรไม่ถูกต้อง"
    sid = next_id(db)
    db["suppliers"][sid] = {"name": name, "phone": phone}
    log(db, user, "supplier_create", name)
    return None


def create_po(db, user, sid, pid, qty_text):
    if sid not in db["suppliers"] or pid not in db["products"]:
        return "เลือกผู้ขายและสินค้าให้ถูกต้อง"
    n, e = to_num(qty_text, int, "จำนวนสั่งซื้อ", 1)
    if e:
        return e
    poid = next_id(db)
    db["pos"][poid] = {"sid": sid, "pid": pid, "qty": n, "status": "pending", "ts": now(), "user": user}
    log(db, user, "po_create", "PO#%s %s x%d" % (poid, db["products"][pid]["sku"], n))
    return None


def receive_po(db, user, poid):
    po = db["pos"].get(poid)
    if not po:
        return "ไม่พบใบสั่งซื้อ"
    if po["status"] != "pending":
        return "ใบสั่งซื้อนี้รับของแล้ว"
    err = move_stock(db, user, po["pid"], "in", str(po["qty"]), "รับตาม PO#" + poid)
    if not err:
        po["status"] = "received"
    return err
