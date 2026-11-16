"""Wzxy-Hosting Pro API. Uploaded source is stored, never executed here."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

BASE = Path(__file__).parent
DATA = BASE / "data"
PROJECTS_DIR = DATA / "projects"
DB = DATA / "wzxy.sqlite3"
LEGACY_DB = DATA / "projects.json"
MAX_UPLOAD = 5 * 1024 * 1024
LANGUAGES = {"Python", "JavaScript", "Java", "PHP", "HTML/CSS", "Other"}
PLANS = [
    {"id": "starter", "name": "Starter", "price_cents": 50, "currency": "USD", "period_days": 30},
    {"id": "pro", "name": "Pro", "price_cents": 100, "currency": "USD", "period_days": 30},
    {"id": "max", "name": "Max", "price_cents": 200, "currency": "USD", "period_days": 30},
    {"id": "ultra", "name": "Ultra", "price_cents": 250, "currency": "USD", "period_days": 30},
    {"id": "premium", "name": "Premium", "price_cents": 350, "currency": "USD", "period_days": 30},
]
PLAN_BY_ID = {plan["id"]: plan for plan in PLANS}
PASSWORD_ITERATIONS = 310_000
DATA.mkdir(exist_ok=True)
PROJECTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Wzxy-Hosting Pro API", version="0.2.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("WZXY_SESSION_SECRET") or secrets.token_urlsafe(48),
    session_cookie="wzxy_session",
    same_site="lax",
    https_only=os.environ.get("WZXY_HTTPS_ONLY", "0") == "1",
    max_age=60 * 60 * 12,
)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db() -> None:
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL, language TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, name COLLATE NOCASE)
        );
        CREATE TABLE IF NOT EXISTS project_files (
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            filename TEXT NOT NULL, size INTEGER NOT NULL CHECK(size >= 0),
            PRIMARY KEY(project_id, filename)
        );
        CREATE TABLE IF NOT EXISTS payment_orders (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            plan_id TEXT NOT NULL, amount_cents INTEGER NOT NULL, currency TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING', provider TEXT NOT NULL DEFAULT 'ABA_PAYWAY',
            provider_txn_id TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            paid_at TEXT, expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            plan_id TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, order_id TEXT NOT NULL UNIQUE REFERENCES payment_orders(id)
        );
        CREATE INDEX IF NOT EXISTS idx_payment_orders_user ON payment_orders(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id, expires_at DESC);
        """)


init_db()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)).hex()
        return hmac.compare_digest(actual, digest)
    except (ValueError, TypeError):
        return False


def current_user(request: Request) -> dict:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(401, "Please sign in")
    with connect() as db:
        row = db.execute("SELECT id,email FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        request.session.clear()
        raise HTTPException(401, "Please sign in")
    return dict(row)


def require_csrf(request: Request) -> None:
    expected = request.session.get("csrf")
    supplied = request.headers.get("x-csrf-token")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise HTTPException(403, "Invalid or missing CSRF token")


def owned_project(project_id: str, user_id: str) -> dict:
    with connect() as db:
        row = db.execute("SELECT id,user_id,name,language FROM projects WHERE id=? AND user_id=?", (project_id, user_id)).fetchone()
    if row is None:
        # Do not reveal whether another user's project exists.
        raise HTTPException(404, "Project not found")
    return dict(row)


def safe_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "-", name).strip(".-")[:48]
    if not cleaned or cleaned in {".", ".."}:
        raise HTTPException(400, "Invalid project name")
    return cleaned


class Credentials(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10, max_length=128)


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=48)
    language: str


@app.get("/", response_class=HTMLResponse)
def home():
    return (BASE / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Wzxy-Hosting Pro", "version": "0.2.0"}


@app.post("/api/register")
def register(payload: Credentials, request: Request):
    email = payload.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(400, "Enter a valid email address")
    if len(payload.password) < 10:
        raise HTTPException(400, "Password must be at least 10 characters")
    user_id = uuid4().hex
    try:
        with connect() as db:
            db.execute("INSERT INTO users(id,email,password_hash) VALUES(?,?,?)", (user_id, email, password_hash(payload.password)))
            # One-time migration: existing starter projects belong to the first account created.
            if LEGACY_DB.exists():
                try:
                    legacy = json.loads(LEGACY_DB.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    legacy = []
                for item in legacy if isinstance(legacy, list) else []:
                    pid, name, language = item.get("id"), item.get("name"), item.get("language")
                    if pid and name and language in LANGUAGES and (PROJECTS_DIR / pid).is_dir():
                        db.execute("INSERT OR IGNORE INTO projects(id,user_id,name,language) VALUES(?,?,?,?)", (pid, user_id, safe_name(name), language))
                        for old_file in (PROJECTS_DIR / pid).iterdir():
                            if old_file.is_file() and not old_file.is_symlink():
                                db.execute("INSERT OR IGNORE INTO project_files(project_id,filename,size) VALUES(?,?,?)", (pid, old_file.name, old_file.stat().st_size))
                LEGACY_DB.rename(LEGACY_DB.with_suffix(".json.migrated"))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with that email already exists")
    request.session.clear()
    request.session.update(user_id=user_id, csrf=secrets.token_urlsafe(32))
    return {"id": user_id, "email": email, "csrf_token": request.session["csrf"]}


@app.post("/api/login")
def login(payload: Credentials, request: Request):
    with connect() as db:
        row = db.execute("SELECT id,email,password_hash FROM users WHERE email=?", (payload.email.strip().lower(),)).fetchone()
    if row is None or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(401, "Email or password is incorrect")
    request.session.clear()
    request.session.update(user_id=row["id"], csrf=secrets.token_urlsafe(32))
    return {"id": row["id"], "email": row["email"], "csrf_token": request.session["csrf"]}


@app.get("/api/me")
def me(request: Request):
    user = current_user(request)
    return {**user, "csrf_token": request.session.get("csrf")}


@app.post("/api/logout")
def logout(request: Request, user: dict = Depends(current_user)):
    require_csrf(request)
    request.session.clear()
    return {"ok": True}


@app.get("/api/projects")
def list_projects(user: dict = Depends(current_user)):
    with connect() as db:
        rows = db.execute("""SELECT p.id,p.name,p.language,
            (SELECT COUNT(*) FROM project_files f WHERE f.project_id=p.id) AS files
            FROM projects p WHERE p.user_id=? ORDER BY p.created_at DESC""", (user["id"],)).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/projects")
def create_project(payload: ProjectIn, request: Request, user: dict = Depends(current_user)):
    require_csrf(request)
    if payload.language not in LANGUAGES:
        raise HTTPException(400, "Unsupported language")
    name = safe_name(payload.name)
    project_id = uuid4().hex[:12]
    folder = PROJECTS_DIR / project_id
    try:
        with connect() as db:
            db.execute("INSERT INTO projects(id,user_id,name,language) VALUES(?,?,?,?)", (project_id, user["id"], name, payload.language))
        folder.mkdir()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Project name already exists")
    return {"id": project_id, "name": name, "language": payload.language, "files": 0}


@app.get("/api/projects/{project_id}/files")
def list_files(project_id: str, user: dict = Depends(current_user)):
    owned_project(project_id, user["id"])
    with connect() as db:
        rows = db.execute("SELECT filename,size FROM project_files WHERE project_id=? ORDER BY filename", (project_id,)).fetchall()
    return {"files": [dict(row) for row in rows]}


@app.post("/api/projects/{project_id}/files")
async def upload_file(project_id: str, request: Request, file: UploadFile = File(...), user: dict = Depends(current_user)):
    require_csrf(request)
    owned_project(project_id, user["id"])
    raw_name = file.filename or ""
    if not raw_name or raw_name in {".", ".."} or "/" in raw_name or "\\" in raw_name or len(raw_name) > 120 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]*", raw_name):
        raise HTTPException(400, "Invalid filename; use letters, numbers, dots, dashes or underscores")
    content = await file.read(MAX_UPLOAD + 1)
    await file.close()
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, "File too large (5 MiB maximum)")
    folder = PROJECTS_DIR / project_id
    folder.mkdir(exist_ok=True)
    target = folder / raw_name
    try:
        with target.open("xb") as stream:
            stream.write(content)
        with connect() as db:
            db.execute("INSERT INTO project_files(project_id,filename,size) VALUES(?,?,?)", (project_id, raw_name, len(content)))
    except FileExistsError:
        raise HTTPException(409, "A file with that name already exists")
    except sqlite3.IntegrityError:
        target.unlink(missing_ok=True)
        raise HTTPException(409, "A file with that name already exists")
    return {"uploaded": raw_name, "size": len(content)}


@app.delete("/api/projects/{project_id}/files/{filename}")
def delete_file(project_id: str, filename: str, request: Request, user: dict = Depends(current_user)):
    require_csrf(request)
    owned_project(project_id, user["id"])
    if Path(filename).name != filename:
        raise HTTPException(400, "Invalid filename")
    target = PROJECTS_DIR / project_id / filename
    with connect() as db:
        row = db.execute("SELECT filename FROM project_files WHERE project_id=? AND filename=?", (project_id, filename)).fetchone()
        if row is None:
            raise HTTPException(404, "File not found")
        target.unlink(missing_ok=True)
        db.execute("DELETE FROM project_files WHERE project_id=? AND filename=?", (project_id, filename))
    return {"deleted": filename}


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: str, request: Request, user: dict = Depends(current_user)):
    require_csrf(request)
    owned_project(project_id, user["id"])
    with connect() as db:
        db.execute("DELETE FROM projects WHERE id=? AND user_id=?", (project_id, user["id"]))
    folder = PROJECTS_DIR / project_id
    if folder.exists():
        import shutil
        shutil.rmtree(folder)
    return {"deleted": project_id}




@app.get("/api/billing/plans")
def billing_plans():
    return [{**p, "price": f"{p['price_cents'] / 100:.2f}"} for p in PLANS]


@app.get("/api/billing/me")
def billing_me(user: dict = Depends(current_user)):
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        sub = db.execute("""SELECT s.plan_id,s.status,s.started_at,s.expires_at,o.provider
            FROM subscriptions s JOIN payment_orders o ON o.id=s.order_id
            WHERE s.user_id=? AND s.status='ACTIVE' AND s.expires_at>? ORDER BY s.expires_at DESC LIMIT 1""",
            (user["id"], now)).fetchone()
        rows = db.execute("""SELECT id,plan_id,amount_cents,currency,status,provider,created_at,paid_at
            FROM payment_orders WHERE user_id=? ORDER BY created_at DESC LIMIT 20""", (user["id"],)).fetchall()
    active = dict(sub) if sub else None
    if active:
        active["plan_name"] = PLAN_BY_ID.get(active["plan_id"], {}).get("name", active["plan_id"])
    return {"subscription": active, "orders": [dict(r) for r in rows]}


@app.post("/api/billing/orders")
def create_payment_order(payload: dict, request: Request, user: dict = Depends(current_user)):
    require_csrf(request)
    plan_id = str(payload.get("plan_id", "")).lower()
    plan = PLAN_BY_ID.get(plan_id)
    if not plan:
        raise HTTPException(400, "Unknown hosting plan")
    order_id = "WZ" + uuid4().hex[:18].upper()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat()
    with connect() as db:
        db.execute("""INSERT INTO payment_orders(id,user_id,plan_id,amount_cents,currency,status,provider,expires_at)
            VALUES(?,?,?,?,?,'PENDING','ABA_PAYWAY',?)""",
            (order_id, user["id"], plan_id, plan["price_cents"], plan["currency"], expires))
    # Live ABA checkout is intentionally not fabricated. A merchant sandbox account and
    # its official credentials are required before creating a real checkout URL.
    return {"order_id": order_id, "plan": plan["name"], "amount": f"{plan['price_cents']/100:.2f}",
            "currency": plan["currency"], "status": "PENDING",
            "message": "Order created. ABA PayWay sandbox credentials are required to start a real checkout."}


@app.post("/api/billing/orders/{order_id}/demo-pay")
def demo_pay(order_id: str, request: Request, user: dict = Depends(current_user)):
    require_csrf(request)
    if os.environ.get("WZXY_ENABLE_DEMO_PAYMENTS") != "1":
        raise HTTPException(403, "Demo payments are disabled. Enable only in a local test environment.")
    now = datetime.now(timezone.utc)
    with connect() as db:
        order = db.execute("SELECT * FROM payment_orders WHERE id=? AND user_id=?", (order_id, user["id"])).fetchone()
        if order is None:
            raise HTTPException(404, "Order not found")
        if order["status"] == "PAID":
            return {"ok": True, "status": "PAID", "demo": True, "message": "This demo order was already completed."}
        if order["status"] != "PENDING" or datetime.fromisoformat(order["expires_at"]) <= now:
            raise HTTPException(409, "Order is not payable")
        started = now.isoformat()
        expiry = (now + timedelta(days=30)).isoformat()
        db.execute("UPDATE payment_orders SET status='PAID',provider_txn_id=?,paid_at=? WHERE id=? AND status='PENDING'",
                   ("DEMO-" + order_id, started, order_id))
        db.execute("UPDATE subscriptions SET status='EXPIRED' WHERE user_id=? AND status='ACTIVE'", (user["id"],))
        db.execute("INSERT INTO subscriptions(id,user_id,plan_id,status,started_at,expires_at,order_id) VALUES(?,?,?,'ACTIVE',?,?,?)",
                   (uuid4().hex, user["id"], order["plan_id"], started, expiry, order_id))
    return {"ok": True, "status": "PAID", "demo": True, "message": "Demo payment accepted. No money was charged; this is not a real ABA payment."}
