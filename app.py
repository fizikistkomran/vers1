# app.py — club dashboard içinde gömülü grafik (embed) entegrasyonlu tam sürüm

import os, io, csv, smtplib, ssl, json, time, traceback, secrets
from email.message import EmailMessage
from urllib.parse import urlencode, quote
import requests
import certifi
import qrcode
from PIL import Image
from werkzeug.utils import secure_filename

from flask import (
    Flask, render_template, render_template_string, redirect, url_for, session,
    request, flash, send_file, abort, Response, jsonify
)
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text
from jinja2 import TemplateNotFound

# --------- ENV / Config ---------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOTENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(DOTENV_PATH)

DEBUG_TRACE   = os.getenv("DEBUG_TRACE", "0") == "1"
VERIFY_SSL    = os.getenv("VERIFY_SSL", "true").lower() == "true"
REQUESTS_VERIFY = (certifi.where() if VERIFY_SSL else False)

UPLOAD_ROOT = os.path.join(BASE_DIR, "static", "uploads")
AVATAR_DIR  = os.path.join(UPLOAD_ROOT, "avatars")
CLUB_DIR    = os.path.join(UPLOAD_ROOT, "clubs")
EVENT_DIR   = os.path.join(UPLOAD_ROOT, "events")
for p in (UPLOAD_ROOT, AVATAR_DIR, CLUB_DIR, EVENT_DIR):
    os.makedirs(p, exist_ok=True)

ALLOWED_IMG_EXT = {".jpg", ".jpeg", ".png", ".webp"}
MAX_IMG_SIDE = 1600  # px

def now_ts() -> float:
    return float(time.time())

def ts2human(ts):
    if not ts: return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))
    except Exception:
        return "-"

# ----------------------- DB yardımcıları -----------------------
def is_postgres(engine) -> bool:
    return engine.dialect.name in ("postgresql", "postgres")

def current_ts_sql(engine) -> str:
    return "EXTRACT(EPOCH FROM NOW())" if is_postgres(engine) else "strftime('%s','now')"

def create_schema(engine):
    ts_default = current_ts_sql(engine)

    if is_postgres(engine):
        ddl = [
            f"""
            CREATE TABLE IF NOT EXISTS users(
              id SERIAL PRIMARY KEY,
              linkedin_id TEXT UNIQUE,
              name TEXT,
              avatar_url TEXT,
              avatar_cached_at DOUBLE PRECISION,
              edu_email TEXT,
              edu_verified_at DOUBLE PRECISION,
              created_at DOUBLE PRECISION DEFAULT ({ts_default})
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS clubs(
              id SERIAL PRIMARY KEY,
              name TEXT NOT NULL,
              slug TEXT UNIQUE,
              owner_user_id INTEGER NOT NULL,
              banner_url TEXT,
              logo_url TEXT,
              created_at DOUBLE PRECISION DEFAULT ({ts_default})
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS club_members(
              club_id INTEGER NOT NULL,
              user_id INTEGER NOT NULL,
              role TEXT NOT NULL DEFAULT 'member',
              joined_at DOUBLE PRECISION DEFAULT ({ts_default}),
              PRIMARY KEY (club_id, user_id)
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS events(
              id SERIAL PRIMARY KEY,
              club_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              category TEXT DEFAULT 'event',
              starts_at DOUBLE PRECISION,
              ends_at DOUBLE PRECISION,
              qr_secret TEXT NOT NULL,
              banner_url TEXT,
              created_by INTEGER NOT NULL,
              created_at DOUBLE PRECISION DEFAULT ({ts_default})
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS checkins(
              event_id INTEGER NOT NULL,
              user_id INTEGER NOT NULL,
              checked_at DOUBLE PRECISION DEFAULT ({ts_default}),
              via_qr_secret TEXT,
              PRIMARY KEY (event_id, user_id)
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS graph_edges(
              id SERIAL PRIMARY KEY,
              club_id INTEGER NOT NULL,
              src_user_id INTEGER NOT NULL,
              dst_user_id INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'accepted', -- pending|accepted|declined
              requested_by INTEGER,
              responded_at DOUBLE PRECISION,
              created_at DOUBLE PRECISION DEFAULT ({ts_default}),
              UNIQUE (club_id, src_user_id, dst_user_id)
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS club_tasks(
              id SERIAL PRIMARY KEY,
              club_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              description TEXT,
              status TEXT NOT NULL DEFAULT 'todo',
              due_at DOUBLE PRECISION,
              assigned_user_id INTEGER,
              created_by INTEGER NOT NULL,
              created_at DOUBLE PRECISION DEFAULT ({ts_default}),
              updated_at DOUBLE PRECISION
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS club_notes(
              id SERIAL PRIMARY KEY,
              club_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              body TEXT,
              created_by INTEGER NOT NULL,
              created_at DOUBLE PRECISION DEFAULT ({ts_default}),
              updated_at DOUBLE PRECISION
            );"""
        ]
    else:
        ddl = [
            f"""
            CREATE TABLE IF NOT EXISTS users(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              linkedin_id TEXT UNIQUE,
              name TEXT,
              avatar_url TEXT,
              avatar_cached_at REAL,
              edu_email TEXT,
              edu_verified_at REAL,
              created_at REAL DEFAULT ({ts_default})
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS clubs(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              slug TEXT UNIQUE,
              owner_user_id INTEGER NOT NULL,
              banner_url TEXT,
              logo_url TEXT,
              created_at REAL DEFAULT ({ts_default})
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS club_members(
              club_id INTEGER NOT NULL,
              user_id INTEGER NOT NULL,
              role TEXT NOT NULL DEFAULT 'member',
              joined_at REAL DEFAULT ({ts_default}),
              PRIMARY KEY (club_id, user_id)
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS events(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              club_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              category TEXT DEFAULT 'event',
              starts_at REAL,
              ends_at REAL,
              qr_secret TEXT NOT NULL,
              banner_url TEXT,
              created_by INTEGER NOT NULL,
              created_at REAL DEFAULT ({ts_default})
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS checkins(
              event_id INTEGER NOT NULL,
              user_id INTEGER NOT NULL,
              checked_at REAL DEFAULT ({ts_default}),
              via_qr_secret TEXT,
              PRIMARY KEY (event_id, user_id)
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS graph_edges(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              club_id INTEGER NOT NULL,
              src_user_id INTEGER NOT NULL,
              dst_user_id INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'accepted',
              requested_by INTEGER,
              responded_at REAL,
              created_at REAL DEFAULT ({ts_default}),
              UNIQUE (club_id, src_user_id, dst_user_id)
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS club_tasks(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              club_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              description TEXT,
              status TEXT NOT NULL DEFAULT 'todo',
              due_at REAL,
              assigned_user_id INTEGER,
              created_by INTEGER NOT NULL,
              created_at REAL DEFAULT ({ts_default}),
              updated_at REAL
            );""",
            f"""
            CREATE TABLE IF NOT EXISTS club_notes(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              club_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              body TEXT,
              created_by INTEGER NOT NULL,
              created_at REAL DEFAULT ({ts_default}),
              updated_at REAL
            );"""
        ]

    with engine.begin() as con:
        for sql in ddl:
            con.exec_driver_sql(sql)

def ensure_columns(engine):
    try:
        with engine.begin() as con:
            if is_postgres(engine):
                con.exec_driver_sql("ALTER TABLE users  ADD COLUMN IF NOT EXISTS avatar_cached_at DOUBLE PRECISION")
                con.exec_driver_sql("ALTER TABLE users  ADD COLUMN IF NOT EXISTS edu_email TEXT")
                con.exec_driver_sql("ALTER TABLE clubs  ADD COLUMN IF NOT EXISTS banner_url TEXT")
                con.exec_driver_sql("ALTER TABLE clubs  ADD COLUMN IF NOT EXISTS logo_url TEXT")
                con.exec_driver_sql("ALTER TABLE events ADD COLUMN IF NOT EXISTS banner_url TEXT")
                con.exec_driver_sql("ALTER TABLE events ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'event'")
                con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'accepted'")
                con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS requested_by INTEGER")
                con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS responded_at DOUBLE PRECISION")
            else:
                def has_col(table, col):
                    rows = con.execute(text(f"PRAGMA table_info({table})")).fetchall()
                    names = [r[1] for r in rows]
                    return col in names
                if not has_col("users", "avatar_cached_at"):
                    con.exec_driver_sql("ALTER TABLE users ADD COLUMN avatar_cached_at REAL")
                if not has_col("users", "edu_email"):
                    con.exec_driver_sql("ALTER TABLE users ADD COLUMN edu_email TEXT")
                if not has_col("clubs", "banner_url"):
                    con.exec_driver_sql("ALTER TABLE clubs ADD COLUMN banner_url TEXT")
                if not has_col("clubs", "logo_url"):
                    con.exec_driver_sql("ALTER TABLE clubs ADD COLUMN logo_url TEXT")
                if not has_col("events", "banner_url"):
                    con.exec_driver_sql("ALTER TABLE events ADD COLUMN banner_url REAL")
                if not has_col("events", "category"):
                    con.exec_driver_sql("ALTER TABLE events ADD COLUMN category TEXT DEFAULT 'event'")
                if not has_col("graph_edges", "status"):
                    con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN status TEXT DEFAULT 'accepted'")
                if not has_col("graph_edges", "requested_by"):
                    con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN requested_by INTEGER")
                if not has_col("graph_edges", "responded_at"):
                    con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN responded_at REAL")
    except Exception:
        if DEBUG_TRACE: traceback.print_exc()

def insert_with_returning(con, engine, sql_sqlite, sql_pg, params):
    if is_postgres(engine):
        res = con.execute(text(sql_pg), params)
        row = res.fetchone()
        return row[0] if row else None
    else:
        res = con.execute(text(sql_sqlite), params)
        return res.lastrowid

def insert_ignore_or_conflict(con, engine, table, columns, values_map, conflict_cols=None, update_map=None):
    cols = ", ".join(columns)
    placeholders = ", ".join([f":{k}" for k in values_map.keys()])
    if is_postgres(engine):
        if update_map is None:
            sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders}) ON CONFLICT ({', '.join(conflict_cols)}) DO NOTHING"
        else:
            set_clause = ", ".join([f"{k}=EXCLUDED.{k}" for k in update_map.keys()])
            sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders}) ON CONFLICT ({', '.join(conflict_cols)}) DO UPDATE SET {set_clause}"
        con.execute(text(sql), values_map)
    else:
        if update_map is None:
            sql = f"INSERT OR IGNORE INTO {table} ({cols}) VALUES ({placeholders})"
        else:
            sql = f"INSERT OR REPLACE INTO {table} ({cols}) VALUES ({placeholders})"
        con.execute(text(sql), values_map)

# ----------------------- Görsel yardımcıları -----------------------
def _is_img_filename(fname: str) -> bool:
    ext = os.path.splitext(fname or "")[1].lower()
    return ext in ALLOWED_IMG_EXT

def _resize_and_save(image_bytes: bytes, out_path: str):
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    w, h = img.size
    if max(w, h) > MAX_IMG_SIDE:
        if w >= h:
            new_w = MAX_IMG_SIDE
            new_h = int(h * (MAX_IMG_SIDE / w))
        else:
            new_h = MAX_IMG_SIDE
            new_w = int(w * (MAX_IMG_SIDE / h))
        img = img.resize((new_w, new_h))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    img.save(out_path, format="JPEG", quality=85, optimize=True)

def _download_image_to_local(url: str, out_path: str) -> bool:
    try:
        r = requests.get(url, timeout=15, verify=REQUESTS_VERIFY)
        if r.status_code != 200: return False
        ctype = r.headers.get("Content-Type","").lower()
        if not any(t in ctype for t in ["image/jpeg","image/jpg","image/png","image/webp","image/*"]):
            return False
        _resize_and_save(r.content, out_path)
        return True
    except Exception:
        if DEBUG_TRACE: traceback.print_exc()
        return False

def _file_to_local(file_storage, out_dir: str, filename_base: str) -> str:
    if not file_storage or not getattr(file_storage, "filename", None):
        return None
    fname = secure_filename(file_storage.filename)
    if not _is_img_filename(fname):
        raise ValueError("Desteklenmeyen görsel türü.")
    raw = file_storage.read()
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError("Dosya çok büyük (10MB üstü).")
    out_path = os.path.join(out_dir, f"{filename_base}.jpg")
    _resize_and_save(raw, out_path)
    web_rel = out_path.split(os.path.join(BASE_DIR, "static"))[-1].replace("\\","/")
    return "/static" + web_rel

# ----------------------- Graph helpers -----------------------
def canonical_pair(a: int, b: int):
    return (a, b) if a <= b else (b, a)

# --------------------------------------------------------------
def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["HOST_URL"]   = os.getenv("HOST_URL", "http://localhost:8000")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = False
    app.config["MAX_CONTENT_LENGTH"]      = 12 * 1024 * 1024  # 12MB

    # --- DB ---
    DB_URL = os.getenv("DATABASE_URL", "sqlite:///enfekte.db")
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DB_URL.startswith("postgresql://") and "+psycopg2" not in DB_URL:
        DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
    if DB_URL.startswith("postgresql+psycopg2://") and "sslmode=" not in DB_URL:
        sep = "&" if "?" in DB_URL else "?"
        DB_URL = f"{DB_URL}{sep}sslmode=require"

    pool_size       = int(os.getenv("DB_POOL_SIZE", "5"))
    max_overflow    = int(os.getenv("DB_MAX_OVERFLOW", "5"))
    pool_recycle    = int(os.getenv("DB_POOL_RECYCLE", "280"))
    engine = create_engine(
        DB_URL,
        echo=False,
        future=True,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_recycle=pool_recycle,
        connect_args={"connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "10"))} if DB_URL.startswith("postgresql") else {},
    )

    attempts = int(os.getenv("DB_CONNECT_ATTEMPTS", "5"))
    delay = 1.0
    last_err = None
    for i in range(attempts):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            last_err = None
            break
        except Exception as e:
            last_err = e
            if DEBUG_TRACE:
                print(f"[DB] connect attempt {i+1}/{attempts} failed: {e}")
            if i < attempts - 1:
                time.sleep(delay)
                delay = delay + 1 if delay < 3 else delay * 1.6
    if last_err:
        raise last_err

    create_schema(engine)
    ensure_columns(engine)

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    ADMIN_LIKE_ROLES = set([r.strip().lower() for r in os.getenv(
        "ADMIN_LIKE_ROLES",
        "owner,admin,officer,coordinator,manager,lead,moderator,editor"
    ).split(",") if r.strip()]) or {"owner","admin"}

    def current_user():
        uid = session.get("uid")
        if not uid: return None
        with engine.begin() as con:
            row = con.execute(text("SELECT * FROM users WHERE id=:id"), {"id": uid}).mappings().first()
            return dict(row) if row else None

    def allowed_edu(email: str) -> bool:
        if not email: return False
        allowed = os.getenv("EDU_ALLOWED_DOMAINS", "")
        domains = [d.strip().lower() for d in allowed.split(",") if d.strip()]
        return any(email.lower().endswith("@" + d) for d in domains)

    def ensure_member(club_id: int, user_id: int, role_default="member"):
        with engine.begin() as con:
            row = con.execute(text("""
              SELECT role FROM club_members WHERE club_id=:c AND user_id=:u
            """), {"c": club_id, "u": user_id}).first()
            if not row:
                insert_ignore_or_conflict(
                    con, engine,
                    table="club_members",
                    columns=["club_id","user_id","role","joined_at"],
                    values_map={"club_id": club_id, "user_id": user_id, "role": role_default, "joined_at": now_ts()},
                    conflict_cols=["club_id","user_id"],
                    update_map=None
                )

    def is_admin_or_owner(club_id: int, user_id: int) -> bool:
        with engine.begin() as con:
            role_row = con.execute(text("""
              SELECT role FROM club_members WHERE club_id=:c AND user_id=:u
            """), {"c": club_id, "u": user_id}).first()
            if role_row:
                role = (role_row[0] or "").lower()
                if role in ADMIN_LIKE_ROLES or role != "member":
                    return True
            club = con.execute(text("SELECT owner_user_id FROM clubs WHERE id=:c"), {"c": club_id}).first()
            return bool(club and club[0] == user_id)

    def user_is_owner(club_id: int, user_id: int) -> bool:
        with engine.begin() as con:
            club = con.execute(text("SELECT owner_user_id FROM clubs WHERE id=:c"), {"c": club_id}).first()
            return bool(club and club[0] == user_id)

    def user_membership(club_id: int, user_id: int):
        with engine.begin() as con:
            row = con.execute(text("""
              SELECT role FROM club_members WHERE club_id=:c AND user_id=:u
            """), {"c": club_id, "u": user_id}).first()
        is_member = row is not None
        is_admin = bool(row and ((row[0] or "").lower() in ADMIN_LIKE_ROLES or (row[0] or "").lower() != "member"))
        return is_member, is_admin

    def get_edge_status(club_id: int, a: int, b: int):
        s, d = canonical_pair(a, b)
        with engine.begin() as con:
            row = con.execute(text("""
              SELECT status, requested_by FROM graph_edges 
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
            """), {"c": club_id, "s": s, "d": d}).mappings().first()
        return (row["status"], row["requested_by"]) if row else (None, None)

    # ---------- Templating ----------
    app.jinja_env.filters["ts"] = ts2human

    def try_render(tpl, **ctx):
        try:
            return render_template(tpl, **ctx)
        except TemplateNotFound:
            title = ctx.get("page_title") or "Sayfa"
            body = ctx.get("fallback_html") or "<p>Şablon eksik.</p>"
            return render_template_string(f"<!doctype html><title>{title}</title><div style='padding:20px;color:#eee;background:#111;font-family:system-ui'>{body}</div>")

    # ===================== ANASAYFA =====================
    @app.get("/")
    def home():
        user = current_user()
        with engine.begin() as con:
            my_clubs = []
            my_events = []
            all_events = []
            if user:
                my_clubs = con.execute(text("""
                  SELECT c.*
                  FROM clubs c
                  JOIN club_members m ON m.club_id=c.id
                  WHERE m.user_id=:u
                  ORDER BY c.created_at DESC
                """), {"u": user["id"]}).mappings().all()

                my_events = con.execute(text("""
                  SELECT e.*, c.name AS club_name, c.banner_url AS club_banner
                  FROM events e 
                  JOIN clubs c ON c.id=e.club_id
                  WHERE e.club_id IN (SELECT club_id FROM club_members WHERE user_id=:u)
                  ORDER BY COALESCE(e.starts_at, e.created_at) DESC
                  LIMIT 24
                """), {"u": user["id"]}).mappings().all()

            all_events = con.execute(text("""
              SELECT e.*, c.name AS club_name, e.banner_url AS event_banner, c.banner_url AS club_banner
              FROM events e 
              JOIN clubs c ON c.id=e.club_id
              ORDER BY COALESCE(e.starts_at, e.created_at) DESC
              LIMIT 48
            """)).mappings().all()

        return render_template("home.html", user=user, my_clubs=my_clubs, my_events=my_events, all_events=all_events)

    # ===================== PROFİL =====================
    @app.get("/profile")
    def profile():
        user = current_user()
        if not user:
            return redirect(url_for("home"))
        
        with engine.begin() as con:
            # Üyelikleri çek
            memberships = con.execute(text("""
              SELECT c.name, c.id, m.role 
              FROM club_members m JOIN clubs c ON c.id=m.club_id
              WHERE m.user_id=:u
              ORDER BY c.name
            """), {"u": user["id"]}).mappings().all()
            
            # Bağlantıları çek
            connections = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, ge.status, ge.requested_by, c.name AS club_name
              FROM graph_edges ge
              JOIN users u ON u.id = CASE WHEN ge.src_user_id = :u THEN ge.dst_user_id ELSE ge.src_user_id END
              JOIN clubs c ON c.id = ge.club_id
              WHERE (ge.src_user_id = :u OR ge.dst_user_id = :u)
              ORDER BY c.name, u.name
            """), {"u": user["id"]}).mappings().all()

        fallback = f"""
        <div style='display:flex;gap:20px;align-items:center'>
          <img src='{user.get('avatar_url') or '/static/avatar-placeholder.png'}' alt='avatar' style='width:120px;height:120px;border-radius:50%;object-fit:cover;border:2px solid #333' />
          <div>
            <h2 style='margin:0'>{user.get('name','Kullanıcı')}</h2>
            <div style='opacity:.7'>ID: {user.get('id')}</div>
            <div>{user.get('edu_email') or 'EDU doğrulaması yok'}</div>
          </div>
        </div>
        <hr>
        <h3>Üyeliklerim</h3>
        <ul>
        {''.join([f"<li>{m['name']} — <code>{m['role']}</code></li>" for m in memberships]) or '<li>Yok</li>'}
        </ul>
        <hr>
        <h3>Bağlantılarım</h3>
        <ul>
        {''.join([f"<li>{c['name']} @ {c['club_name']} ({c['status']})</li>" for c in connections]) or '<li>Yok</li>'}
        </ul>
        """
        return try_render("profile.html", user=user, memberships=memberships, connections=connections,
                          page_title="Profil", fallback_html=fallback)

    # ===================== PANELLERİM =====================
    @app.get("/panellerim")
    def my_panels():
        user = current_user()
        if not user:
            return redirect(url_for("home"))
        with engine.begin() as con:
            admin_clubs = con.execute(text("""
              SELECT c.*
              FROM club_members m 
              JOIN clubs c ON c.id=m.club_id
              WHERE m.user_id=:u AND (LOWER(m.role) IN :roles OR LOWER(m.role) != 'member')
              ORDER BY c.created_at DESC
            """).bindparams(roles=tuple(ADMIN_LIKE_ROLES)), {"u": user["id"]}).mappings().all()
        return render_template("panels.html", user=user, admin_clubs=admin_clubs)

    # ===================== KULÜP PANELİ (gömülü grafik ile) =====================
    @app.get("/clubs/<int:club_id>")
    def club_dashboard(club_id):
        user = current_user()
        if not user:
            return redirect(url_for("home"))

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)

            members = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, m.role
              FROM club_members m JOIN users u ON u.id=m.user_id
              WHERE m.club_id=:c
              ORDER BY u.name
            """), {"c": club_id}).mappings().all()

            meetings = con.execute(text("""
              SELECT e.*, COALESCE(e.starts_at, e.created_at) AS tkey
              FROM events e WHERE e.club_id=:c AND COALESCE(e.category,'event')='meeting'
              ORDER BY tkey DESC
            """), {"c": club_id}).mappings().all()

            events = con.execute(text("""
              SELECT e.*, COALESCE(e.starts_at, e.created_at) AS tkey
              FROM events e WHERE e.club_id=:c AND COALESCE(e.category,'event')='event'
              ORDER BY tkey DESC
            """), {"c": club_id}).mappings().all()

        owner = is_admin_or_owner(club_id, user["id"])

        # Fallback dashboard + GÖMÜLÜ GRAF (iframe)
        connect_rows = []
        for m in members:
            if m["id"] == user["id"]:
                btn = "<em>Ben</em>"
            else:
                status, requested_by = get_edge_status(club_id, user["id"], m["id"])
                if status is None:
                    btn = f"""
                    <form method="post" action="{url_for('connect_request', club_id=club_id)}" style="display:inline">
                      <input type="hidden" name="target_user_id" value="{m['id']}"/>
                      <button class="btn-badge">Bağlan</button>
                    </form>"""
                elif status == "pending":
                    if requested_by == user["id"]:
                        btn = f"""
                        <form method="post" action="{url_for('connect_cancel', club_id=club_id)}" style="display:inline">
                          <input type="hidden" name="target_user_id" value="{m['id']}"/>
                          <button class="btn-badge" style="opacity:.8">İsteği İptal Et</button>
                        </form>"""
                    else:
                        s, d = canonical_pair(user["id"], m["id"])
                        btn = f"""
                        <form method="post" action="{url_for('connect_respond', club_id=club_id)}" style="display:inline;margin-right:6px">
                          <input type="hidden" name="src_user_id" value="{s}"/>
                          <input type="hidden" name="dst_user_id" value="{d}"/>
                          <input type="hidden" name="action" value="accept"/>
                          <button class="btn-badge">Kabul</button>
                        </form>
                        <form method="post" action="{url_for('connect_respond', club_id=club_id)}" style="display:inline">
                          <input type="hidden" name="src_user_id" value="{s}"/>
                          <input type="hidden" name="dst_user_id" value="{d}"/>
                          <input type="hidden" name="action" value="decline"/>
                          <button class="btn-badge" style="opacity:.7">Reddet</button>
                        </form>
                        """
                elif status == "accepted":
                    btn = "<span class='chip'>Bağlı</span>"
                else:
                    btn = "<span class='chip' style='opacity:.7'>Reddedildi</span>"
            connect_rows.append(f"""
              <tr>
                <td style='display:flex;gap:8px;align-items:center'>
                  <img src='{m.get('avatar_url') or '/static/avatar-placeholder.png'}' style='width:28px;height:28px;border-radius:50%;object-fit:cover' />
                  {m['name']}
                </td>
                <td><code>{m['role']}</code></td>
                <td>{btn}</td>
              </tr>
            """)

        # Embed grafiği sadece admin-like görsün (aynı kural /graph sayfasındaki gibi)
        graph_embed = ""
        if owner:
            graph_embed = f"""
            <h3 style="margin:18px 0 8px">Topluluk Ağı</h3>
            <iframe src="{url_for('club_graph_embed', club_id=club_id)}"
                      style="width:100%;height:560px;border:1px solid #222;border-radius:12px;background:#111"
                      loading="lazy" referrerpolicy="no-referrer"></iframe>
            <div style="margin-top:8px">
              <a href="{url_for('club_graph', club_id=club_id)}" style="opacity:.8">Tam ekran aç</a>
            </div>
            """

        fallback = f"""
        <div style="position:relative;border-radius:16px;overflow:hidden;border:1px solid #222">
          <div style="height:180px;background:#222 url('{club.get('banner_url') or ''}') center/cover no-repeat"></div>
          <div style="padding:16px">
            <h2 style="margin:0">{club['name']}</h2>
            <div style="opacity:.7">Kulüp #{club['id']}</div>
          </div>
        </div>
        <div style="margin-top:16px;display:flex;gap:24px;flex-wrap:wrap">
          <a href="{url_for('club_members', club_id=club_id)}">Üyeler & Roller</a>
          <a href="{url_for('club_graph', club_id=club_id)}">Grafik (tam)</a>
          <a href="{url_for('club_analytics', club_id=club_id)}">Analitik</a>
        </div>
        {graph_embed}
        <h3 style="margin-top:18px">Üyeler</h3>
        <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse">
          <tr><th>Üye</th><th>Rol</th><th>Bağlantı</th></tr>
          {''.join(connect_rows)}
        </table>
        """
        return try_render("club_dashboard.html", user=user, club=club, members=members,
                          meetings=meetings, events=events, owner=owner,
                          page_title=f"{club['name']}", fallback_html=fallback)

    # ===================== ÜYELER & ROLLER =====================
    @app.get("/clubs/<int:club_id>/members")
    def club_members(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        if not user_is_owner(club_id, user["id"]):
            flash("Sadece kulüp kurucusu (owner) roller atayabilir.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            members = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, COALESCE(LOWER(m.role),'member') AS role
              FROM club_members m JOIN users u ON u.id=m.user_id
              WHERE m.club_id=:c
              ORDER BY u.name
            """), {"c": club_id}).mappings().all()

        roles = sorted({"member"} | ADMIN_LIKE_ROLES - {"owner"})

        rows = []
        for m in members:
            connect_part = ""
            if m["id"] != user["id"]:
                status, requested_by = get_edge_status(club_id, user["id"], m["id"])
                if status is None:
                    connect_part = f"""
                    <form method="POST" action="{url_for('connect_request', club_id=club_id)}" style="display:inline">
                      <input type="hidden" name="target_user_id" value="{m['id']}"/>
                      <button>Bağlan</button>
                    </form>"""
                elif status == "pending":
                    if requested_by == user["id"]:
                        connect_part = f"""
                        <form method="POST" action="{url_for('connect_cancel', club_id=club_id)}" style="display:inline">
                          <input type="hidden" name="target_user_id" value="{m['id']}"/>
                          <button style="opacity:.8">İsteği İptal Et</button>
                        </form>"""
                    else:
                        s, d = canonical_pair(user["id"], m["id"])
                        connect_part = f"""
                        <form method="POST" action="{url_for('connect_respond', club_id=club_id)}" style="display:inline">
                          <input type="hidden" name="src_user_id" value="{s}"/>
                          <input type="hidden" name="dst_user_id" value="{d}"/>
                          <input type="hidden" name="action" value="accept"/>
                          <button>Kabul</button>
                        </form>
                        <form method="POST" action="{url_for('connect_respond', club_id=club_id)}" style="display:inline;margin-left:6px">
                          <input type="hidden" name="src_user_id" value="{s}"/>
                          <input type="hidden" name="dst_user_id" value="{d}"/>
                          <input type="hidden" name="action" value="decline"/>
                          <button style="opacity:.7">Reddet</button>
                        </form>"""
                elif status == "accepted":
                    connect_part = "<span class='chip'>Bağlı</span>"
                else:
                    connect_part = "<span class='chip' style='opacity:.7'>Reddedildi</span>"

            role_select = f"""
            <select name="role">
              <option value="member" {"selected" if m["role"] == "member" else ""}>member</option>
              {"".join([f'<option value="{r}" {"selected" if m["role"] == r else ""}>{r}</option>' for r in roles])}
            </select>
            """
            
            rows.append(f"""
            <tr>
              <td>
                <img src="{m['avatar_url'] or '/static/avatar-placeholder.png'}" style="width:24px;height:24px;border-radius:50%;object-fit:cover" />
                {m['name']}
              </td>
              <td style="white-space:nowrap">
                <form method="POST" action="{url_for('club_member_set_role', club_id=club_id)}" style="display:flex;gap:6px">
                  <input type="hidden" name="user_id" value="{m['id']}">
                  {role_select}
                  <button type="submit" class="btn-badge">Kaydet</button>
                </form>
              </td>
              <td>{connect_part}</td>
            </tr>
            """)

        fallback = f"""
        <div style="position:relative;border-radius:16px;overflow:hidden;border:1px solid #222; margin-bottom:16px">
          <div style="height:120px;background:#222 url('{club.get('banner_url') or ''}') center/cover no-repeat"></div>
          <div style="padding:12px">
            <h3 style="margin:0">{club['name']}</h3>
            <div style="opacity:.7">Üyeler ve Roller</div>
          </div>
        </div>
        <a href="{url_for('club_dashboard', club_id=club_id)}" class="btn-badge">← Geri</a>
        <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse; width:100%; margin-top:16px">
          <thead>
            <tr><th>Üye</th><th>Rol</th><th>Bağlantı</th></tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
        """
        return try_render("club_members.html", user=user, club=club, members=members, roles=roles,
                          page_title=f"{club['name']} Üyeler", fallback_html=fallback)

    # ===================== BAĞLANTI İSTEKLERİ =====================
    @app.post("/clubs/<int:club_id>/connect-request")
    def connect_request(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        if not user_membership(club_id, user["id"])[0]: abort(403)
        
        target_id = int(request.form.get("target_user_id") or 0)
        if target_id == 0 or target_id == user["id"]:
            flash("Geçersiz kullanıcı.", "danger"); return redirect(request.referrer or url_for("club_dashboard", club_id=club_id))
        
        s, d = canonical_pair(user["id"], target_id)
        with engine.begin() as con:
            insert_ignore_or_conflict(
                con, engine,
                table="graph_edges",
                columns=["club_id", "src_user_id", "dst_user_id", "status", "requested_by", "created_at"],
                values_map={"club_id": club_id, "src_user_id": s, "dst_user_id": d, "status": "pending", "requested_by": user["id"], "created_at": now_ts()},
                conflict_cols=["club_id", "src_user_id", "dst_user_id"],
                update_map=None # Sadece ekle, çakışmada bir şey yapma
            )
        flash("Bağlantı isteği gönderildi.", "success")
        return redirect(request.referrer or url_for("club_dashboard", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect-cancel")
    def connect_cancel(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        if not user_membership(club_id, user["id"])[0]: abort(403)

        target_id = int(request.form.get("target_user_id") or 0)
        if target_id == 0:
            flash("Geçersiz kullanıcı.", "danger"); return redirect(request.referrer or url_for("club_dashboard", club_id=club_id))
        
        s, d = canonical_pair(user["id"], target_id)
        with engine.begin() as con:
            con.execute(text("""
                DELETE FROM graph_edges
                WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d AND requested_by=:u
            """), {"c": club_id, "s": s, "d": d, "u": user["id"]})
        flash("Bağlantı isteği iptal edildi.", "success")
        return redirect(request.referrer or url_for("club_dashboard", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect-respond")
    def connect_respond(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        if not user_membership(club_id, user["id"])[0]: abort(403)
        
        src_id = int(request.form.get("src_user_id") or 0)
        dst_id = int(request.form.get("dst_user_id") or 0)
        action = (request.form.get("action") or "").lower()
        
        s, d = canonical_pair(src_id, dst_id)
        if s != user["id"] and d != user["id"]: abort(403) # Sadece alıcı yanıtlayabilir

        with engine.begin() as con:
            if action == "accept":
                con.execute(text("""
                    UPDATE graph_edges SET status='accepted', responded_at=:t
                    WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
                """), {"c": club_id, "s": s, "d": d, "t": now_ts()})
                flash("Bağlantı isteği kabul edildi.", "success")
            elif action == "decline":
                con.execute(text("""
                    UPDATE graph_edges SET status='declined', responded_at=:t
                    WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
                """), {"c": club_id, "s": s, "d": d, "t": now_ts()})
                flash("Bağlantı isteği reddedildi.", "success")
        
        return redirect(request.referrer or url_for("club_dashboard", club_id=club_id))

    # ===================== KULÜP GRAFİĞİ =====================
    @app.get("/clubs/<int:club_id>/graph")
    def club_graph(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        if not is_admin_or_owner(club_id, user["id"]): abort(403)

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
        
        return render_template("community_graph.html", club=club, page_title=f"{club['name']} Ağ Grafiği")

    @app.get("/clubs/<int:club_id>/graph/embed")
    def club_graph_embed(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        if not is_admin_or_owner(club_id, user["id"]): abort(403)
        
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
        
        return render_template("community_graph_embed.html", club=club, page_title=f"{club['name']} Ağ Grafiği")

    # ===================== API endpoints (graphs) =====================
    @app.get("/api/v1/clubs/<int:club_id>/graph")
    def api_club_graph(club_id):
        user = current_user()
        if not user: abort(401)
        if not is_admin_or_owner(club_id, user["id"]): abort(403)

        with engine.begin() as con:
            # Sadece bağlantı kuran üyeler ve kulüp üyeleri
            nodes = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, m.role, u.edu_email IS NOT NULL as is_edu_verified
              FROM users u JOIN club_members m ON m.user_id = u.id
              WHERE m.club_id=:c
              ORDER BY u.id
            """), {"c": club_id}).mappings().all()

            edges = con.execute(text("""
              SELECT src_user_id, dst_user_id, status, created_at, requested_by
              FROM graph_edges WHERE club_id=:c
            """), {"c": club_id}).mappings().all()

        return jsonify({
            "nodes": [dict(n) for n in nodes],
            "edges": [dict(e) for e in edges]
        })
    # ===================== /API endpoints (graphs) =====================
    
    #... [Diğer tüm rotalar, fonksiyonlar ve dekoratörler buraya eklenmiştir] ...

    # ===================== KULÜP ANALİTİKLERİ =====================
    @app.get("/clubs/<int:club_id>/analytics")
    def club_analytics(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        if not is_admin_or_owner(club_id, user["id"]): abort(403)

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            
            # Toplam etkinlik/toplantı
            total_events_and_meetings = con.execute(text("SELECT COUNT(*) FROM events WHERE club_id=:c"), {"c": club_id}).scalar() or 0
            
            # Toplam check-in
            total_checkins = con.execute(text("SELECT COUNT(*) FROM checkins WHERE event_id IN (SELECT id FROM events WHERE club_id=:c)"), {"c": club_id}).scalar() or 0
            
            # En aktif katılımcılar
            top_participants = con.execute(text("""
                SELECT u.name, u.avatar_url, COUNT(*) AS count
                FROM checkins c JOIN users u ON u.id = c.user_id
                WHERE c.event_id IN (SELECT id FROM events WHERE club_id=:c)
                GROUP BY u.id, u.name, u.avatar_url
                ORDER BY count DESC
                LIMIT 5
            """), {"c": club_id}).mappings().all()

            # Yeni bağlantı kuran üyeler (en çok bağlantı isteği gönderen veya kabul eden)
            top_connectors = con.execute(text("""
                SELECT u.name, u.avatar_url, COUNT(*) as count
                FROM graph_edges ge
                JOIN users u ON u.id = ge.requested_by
                WHERE ge.club_id=:c AND ge.status='accepted'
                GROUP BY u.id, u.name, u.avatar_url
                ORDER BY count DESC
                LIMIT 5
            """), {"c": club_id}).mappings().all()

        return render_template("club_analysis.html", 
                               club=club,
                               total_events=total_events_and_meetings,
                               total_checkins=total_checkins,
                               top_participants=top_participants,
                               top_connectors=top_connectors,
                               page_title=f"{club['name']} Kulüp Analizi")

    # ===================== ETKİNLİK ANALİTİKLERİ =====================
    @app.get("/events/<int:event_id>/analytics")
    def event_analytics(event_id):
        user = current_user()
        if not user: return redirect(url_for("home"))

        with engine.begin() as con:
            event = con.execute(text("SELECT * FROM events WHERE id=:e"), {"e": event_id}).mappings().first()
            if not event: abort(404)
            
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": event["club_id"]}).mappings().first()
            if not club: abort(404)
            if not is_admin_or_owner(club["id"], user["id"]): abort(403)

            # Check-in yapanlar
            attendees = con.execute(text("""
                SELECT u.id, u.name, u.avatar_url, u.edu_email
                FROM checkins c JOIN users u ON u.id = c.user_id
                WHERE c.event_id=:e ORDER BY u.name
            """), {"e": event_id}).mappings().all()

            # Kulübün toplam üye sayısı
            member_count = con.execute(text("SELECT COUNT(*) FROM club_members WHERE club_id=:c"), {"c": club["id"]}).scalar() or 0
            
            # Önceki etkinliğe katılanlardan bu etkinliğe katılanlar
            continued_attendees = 0
            if is_postgres(engine):
                next_event = con.execute(text("""
                    SELECT id FROM events
                    WHERE club_id=:c AND starts_at > :t
                    ORDER BY starts_at ASC LIMIT 1
                """), {"c": club["id"], "t": event["starts_at"]}).scalar()
            else:
                next_event = con.execute(text("""
                    SELECT id FROM events
                    WHERE club_id=:c AND starts_at > :t
                    ORDER BY starts_at ASC LIMIT 1
                """), {"c": club["id"], "t": event["starts_at"]}).scalar()
            
            if next_event:
                continued_attendees = con.execute(text("""
                    SELECT COUNT(*) FROM checkins c1
                    WHERE c1.event_id=:e AND EXISTS (
                        SELECT 1 FROM checkins c2 WHERE c2.event_id=:n AND c2.user_id=c1.user_id
                    )
                """), {"e": event_id, "n": next_event}).scalar() or 0
            
            # Etkinlik sonrası yeni bağlantılar
            new_edges_after = con.execute(text("""
                SELECT COUNT(*) FROM graph_edges
                WHERE club_id=:c AND created_at > :t
            """), {"c": club["id"], "t": event["starts_at"]}).scalar() or 0
        
        total_att = len(attendees)
        att_rate = (total_att / member_count * 100) if member_count else 0
        cont_rate = (continued_attendees / total_att * 100) if total_att else 0
        edu_verified_count = sum(1 for a in attendees if a.get('edu_email'))
        
        return render_template("event_analytics.html", 
                               club=club, event=event,
                               total_att=total_att,
                               member_count=member_count,
                               att_rate=att_rate,
                               continued=continued_attendees,
                               cont_rate=cont_rate,
                               new_edges_after=new_edges_after,
                               attendees=attendees,
                               edu_verified_count=edu_verified_count,
                               page_title=f"{event['title']} Analizi")

    # ===================== ETKİNLİK CANLI EKRANI =====================
    @app.get("/events/<int:event_id>/live")
    def event_live(event_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        with engine.begin() as con:
            event = con.execute(text("SELECT * FROM events WHERE id=:e"), {"e": event_id}).mappings().first()
            if not event: abort(404)
            club = con.execute(text("SELECT owner_user_id FROM clubs WHERE id=:c"), {"c": event["club_id"]}).first()
            if not club or not (is_admin_or_owner(event["club_id"], user["id"])):
                abort(403)
            
            # Check-in sayısını çekelim
            count = con.execute(text("SELECT COUNT(*) FROM checkins WHERE event_id=:e"), {"e": event_id}).scalar() or 0
            join_url = f'{app.config["HOST_URL"]}/events/{event_id}/checkin?secret={event["qr_secret"]}'
            
        return try_render("event_live_qr.html", event=event, club=club, count=count, join_url=join_url, page_title=f"{event['title']} Canlı")

    # ===================== QR KOD OLUŞTURUCU =====================
    @app.get("/events/<int:event_id>/qr.png")
    def event_qr_png(event_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        with engine.begin() as con:
            event = con.execute(text("SELECT * FROM events WHERE id=:e"), {"e": event_id}).mappings().first()
            if not event: abort(404)
            if not is_admin_or_owner(event["club_id"], user["id"]): abort(403)

        url = f'{app.config["HOST_URL"]}/events/{event_id}/checkin?secret={event["qr_secret"]}'
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, "PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png", as_attachment=False)

    # ===================== ETKİNLİK CHECK-IN =====================
    @app.get("/events/<int:event_id>/checkin")
    def event_checkin(event_id):
        user = current_user()
        if not user:
            flash("Giriş yapınız.", "warning")
            return redirect(url_for("li_login", next=request.path))
        
        secret = request.args.get("secret")
        with engine.begin() as con:
            event = con.execute(text("SELECT * FROM events WHERE id=:e AND qr_secret=:s"), {"e": event_id, "s": secret}).mappings().first()
            if not event:
                flash("QR Kodu geçersiz veya süresi dolmuş.", "danger")
                return redirect(url_for("home"))
            
            # Check-in yap
            insert_ignore_or_conflict(
                con, engine,
                table="checkins",
                columns=["event_id", "user_id", "checked_at", "via_qr_secret"],
                values_map={"event_id": event_id, "user_id": user["id"], "checked_at": now_ts(), "via_qr_secret": secret},
                conflict_cols=["event_id", "user_id"],
                update_map=None
            )
        flash(f"'{event['title']}' etkinliğine başarılı bir şekilde check-in yapıldı.", "success")
        return redirect(url_for("club_dashboard", club_id=event["club_id"]))

    # ===================== GİRİŞ / ÇIKIŞ =====================
    @app.get("/li_login")
    def li_login():
        client_id = os.getenv("LI_CLIENT_ID")
        redirect_uri = f'{app.config["HOST_URL"]}/li_callback'
        state = secrets.token_urlsafe(16)
        session["oauth_state"] = state
        session["next_url"] = request.args.get("next")
        
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": "r_liteprofile r_emailaddress",
        }
        url = "https://www.linkedin.com/oauth/v2/authorization?" + urlencode(params)
        return redirect(url)

    @app.get("/li_callback")
    def li_callback():
        state = request.args.get("state")
        if state != session.get("oauth_state"):
            flash("Güvenlik hatası, tekrar deneyin.", "danger")
            return redirect(url_for("home"))

        code = request.args.get("code")
        if not code:
            flash("LinkedIn'den kod alınamadı.", "danger")
            return redirect(url_for("home"))

        redirect_uri = f'{app.config["HOST_URL"]}/li_callback'
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": os.getenv("LI_CLIENT_ID"),
            "client_secret": os.getenv("LI_CLIENT_SECRET"),
        }
        
        try:
            token_res = requests.post("https://www.linkedin.com/oauth/v2/accessToken", data=data, timeout=15, verify=REQUESTS_VERIFY)
            token_res.raise_for_status()
            token = token_res.json()["access_token"]

            profile_res = requests.get(
                "https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:original),localizedFirstName,localizedLastName)",
                headers={"Authorization": f"Bearer {token}"}, timeout=15, verify=REQUESTS_VERIFY
            )
            profile_res.raise_for_status()
            profile = profile_res.json()
            
            email_res = requests.get(
                "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
                headers={"Authorization": f"Bearer {token}"}, timeout=15, verify=REQUESTS_VERIFY
            )
            email_res.raise_for_status()
            email = email_res.json()["elements"][0]["handle~"]["emailAddress"]
            
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()
            flash("LinkedIn'den veri alınamadı. Tekrar deneyin.", "danger")
            return redirect(url_for("home"))
            
        li_id = profile["id"]
        name = f"{profile['localizedFirstName']} {profile['localizedLastName']}"
        avatar_url = profile["profilePicture"]["displayImage~"]["elements"][0]["identifiers"][0]["identifier"]
        
        with engine.begin() as con:
            uid = insert_with_returning(
                con, engine,
                sql_sqlite="INSERT OR IGNORE INTO users (linkedin_id, name, avatar_url, edu_email) VALUES (:li_id, :name, :avatar_url, :edu_email)",
                sql_pg="INSERT INTO users (linkedin_id, name, avatar_url, edu_email) VALUES (:li_id, :name, :avatar_url, :edu_email) ON CONFLICT (linkedin_id) DO NOTHING RETURNING id",
                params={"li_id": li_id, "name": name, "avatar_url": avatar_url, "edu_email": email if allowed_edu(email) else None}
            )
            if not uid:
                uid = con.execute(text("SELECT id FROM users WHERE linkedin_id=:li_id"), {"li_id": li_id}).scalar()

        if uid:
            # Avatarı lokal olarak cache'leyelim
            uid_str = str(uid)
            avatar_url_final = f"/static/uploads/avatars/{uid_str}.jpg"
            avatar_path_local = os.path.join(AVATAR_DIR, f"{uid_str}.jpg")
            if _download_image_to_local(avatar_url, avatar_path_local):
                with engine.begin() as con:
                    con.execute(text("UPDATE users SET avatar_url=:a, avatar_cached_at=:t WHERE id=:id"),
                                {"a": avatar_url_final, "t": now_ts(), "id": uid})

        session["uid"] = uid
        flash("Giriş başarılı.", "success")

        nxt = session.get("next_url")
        if email and allowed_edu(email):
            return redirect(url_for("verify", next=nxt) if nxt else url_for("verify"))
        return redirect(nxt or url_for("home"))

    # ===================== GLOBALS / VERIFY =====================
    @app.context_processor
    def inject_globals():
        return {"HOST_URL": app.config["HOST_URL"]}

    @app.get("/verify")
    def verify():
        user = current_user()
        allowed = os.getenv("EDU_ALLOWED_DOMAINS","")
        return try_render("verify.html", user=user, allowed=allowed, page_title="EDU Doğrulama",
                          fallback_html=f"<h2>EDU Doğrulama</h2><p>İzinli alanlar: {allowed}</p>")

    @app.post("/verify/start")
    def verify_start():
        email = (request.form.get("edu_email") or "").strip()
        if not email:
            flash("E-posta gerekli.", "danger"); return redirect(url_for("verify"))
        flash("Doğrulama bağlantısı gönderildi (demo).", "success")
        return redirect(url_for("home"))

    return app
