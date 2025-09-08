# app.py — friendship graph (connect requests) entegre tam sürüm

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
    """
    Çekirdek tablolar + yeni banner/logo kolonları + görev/not tabloları + graph_edges.
    """
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
              requested_by INTEGER,                    -- isteği başlatan
              responded_at DOUBLE PRECISION,           -- karar zamanı
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
    """
    Eski DB'lerde eksik kolonları güvenli şekilde ekler.
    """
    try:
        with engine.begin() as con:
            if is_postgres(engine):
                # users / clubs / events mevcut eklemeler
                con.exec_driver_sql("ALTER TABLE users  ADD COLUMN IF NOT EXISTS avatar_cached_at DOUBLE PRECISION")
                con.exec_driver_sql("ALTER TABLE users  ADD COLUMN IF NOT EXISTS edu_email TEXT")
                con.exec_driver_sql("ALTER TABLE clubs  ADD COLUMN IF NOT EXISTS banner_url TEXT")
                con.exec_driver_sql("ALTER TABLE clubs  ADD COLUMN IF NOT EXISTS logo_url TEXT")
                con.exec_driver_sql("ALTER TABLE events ADD COLUMN IF NOT EXISTS banner_url TEXT")
                con.exec_driver_sql("ALTER TABLE events ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'event'")
                # graph_edges yeni alanlar
                con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'accepted'")
                con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS requested_by INTEGER")
                con.exec_driver_sql("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS responded_at DOUBLE PRECISION")
            else:
                # sqlite pragma ile kontrol
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
    """Werkzeug FileStorage -> local jpg path; returns web URL under /static/uploads/..."""
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
    # web path:
    web_rel = out_path.split(os.path.join(BASE_DIR, "static"))[-1].replace("\\","/")
    return "/static" + web_rel

# ----------------------- Graph helpers -----------------------
def canonical_pair(a: int, b: int):
    """Undirected edge için kanonik (src,dst) sıralaması"""
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
    # URL'i normalize et (Railway/SQLAlchemy uyumu)
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

    # İlk bağlantıyı birkaç kez dene (soğuk uyanma)
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
        # Açık hata; Railway loglarında net görünür
        raise last_err

    create_schema(engine)
    ensure_columns(engine)

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    # ---------- Helpers ----------
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
            memberships = con.execute(text("""
              SELECT c.name, c.id, m.role 
              FROM club_members m JOIN clubs c ON c.id=m.club_id
              WHERE m.user_id=:u
              ORDER BY c.name
            """), {"u": user["id"]}).mappings().all()

        # Fallback profil şablonu
        fallback = f"""
        <div style='display:flex;gap:20px;align-items:center'>
          <img src='{user.get('avatar_url') or '/static/avatar-placeholder.png'}' alt='avatar' style='width:120px;height:120px;border-radius:50%;object-fit:cover;border:2px solid #333' />
          <div>
            <h2 style='margin:0'>{user.get('name','Kullanıcı')}</h2>
            <div style='opacity:.7'>ID: {user.get('id')}</div>
          </div>
        </div>
        <hr>
        <h3>Üyeliklerim</h3>
        <ul>
        {''.join([f"<li>{m['name']} — <code>{m['role']}</code></li>" for m in memberships]) or '<li>Yok</li>'}
        </ul>
        """
        return try_render("profile.html", user=user, memberships=memberships,
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

    # ===================== KULÜP PANELİ =====================
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
        # Fallback bannerli görünüm + üyelerde bağlan/kabul/iptal
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
                        # gelen isteği kabul/ret
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
          <a href="{url_for('club_graph', club_id=club_id)}">Grafik (beta)</a>
          <a href="{url_for('club_analytics', club_id=club_id)}">Analitik</a>
        </div>
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

        roles = sorted({"member"} | ADMIN_LIKE_ROLES - {"owner"})  # owner ataması buradan yapılmaz

        # Fallback form + bağlanma butonları
        rows = []
        for m in members:
            connect_part = ""
            if m["id"] != user["id"]:
                status, requested_by = get_edge_status(club_id, user["id"], m["id"])
                if status is None:
                    connect_part = f"""
                    <form method="POST" action="{url_for('connect_request', club_id=club_id)}" style="display:inline">
                      <input type="hidden" name="target_user_id" value="{m['id']}"/>
                      <button class="btn-badge">Bağlan</button>
                    </form>"""
                elif status == "pending":
                    if requested_by == user["id"]:
                        connect_part = f"""
                        <form method="POST" action="{url_for('connect_cancel', club_id=club_id)}" style="display:inline">
                          <input type="hidden" name="target_user_id" value="{m['id']}"/>
                          <button class="btn-badge" style="opacity:.8">İsteği İptal Et</button>
                        </form>"""
                    else:
                        s, d = canonical_pair(user["id"], m["id"])
                        connect_part = f"""
                        <form method="POST" action="{url_for('connect_respond', club_id=club_id)}" style="display:inline;margin-right:6px">
                          <input type="hidden" name="src_user_id" value="{s}"/>
                          <input type="hidden" name="dst_user_id" value="{d}"/>
                          <input type="hidden" name="action" value="accept"/>
                          <button class="btn-badge">Kabul</button>
                        </form>
                        <form method="POST" action="{url_for('connect_respond', club_id=club_id)}" style="display:inline">
                          <input type="hidden" name="src_user_id" value="{s}"/>
                          <input type="hidden" name="dst_user_id" value="{d}"/>
                          <input type="hidden" name="action" value="decline"/>
                          <button class="btn-badge" style="opacity:.7">Reddet</button>
                        </form>
                        """
                elif status == "accepted":
                    connect_part = "<span class='chip'>Bağlı</span>"
                else:
                    connect_part = "<span class='chip' style='opacity:.7'>Reddedildi</span>"
            
            rows.append(f"""
            <tr>
              <td style="display:flex;gap:8px;align-items:center">
                <img src="{m.get('avatar_url') or '/static/avatar-placeholder.png'}" style="width:28px;height:28px;border-radius:50%;object-fit:cover" />
                {m['name']}
              </td>
              <td>
                <select name="role" data-user-id="{m['id']}">
                  {''.join([f"<option value='{r}' {'selected' if r == m['role'] else ''}>{r.capitalize()}</option>" for r in roles])}
                </select>
                {' (Owner)' if m['role'] == 'owner' else ''}
              </td>
              <td>{connect_part}</td>
            </tr>
            """)
        
        fallback = f"""
        <a href="{url_for('club_dashboard', club_id=club_id)}">← Geri</a>
        <h2>{club['name']} Üyeleri ve Rolleri</h2>
        <p>Sadece kulüp sahibi (owner) roller atayabilir. Kendinize rol atayamazsınız.</p>
        <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%">
          <tr>
            <th>Üye</th>
            <th>Rol</th>
            <th>Bağlantı Durumu</th>
          </tr>
          {''.join(rows)}
        </table>
        """
        return try_render("club_members.html", user=user, club=club, members=members, roles=roles,
                          page_title=f"{club['name']} Üyeleri", fallback_html=fallback)

    @app.post("/clubs/<int:club_id>/members/update")
    def update_member_role(club_id):
        user = current_user()
        if not user or not user_is_owner(club_id, user["id"]):
            return abort(403)
        
        target_id = request.form.get("user_id", type=int)
        new_role = (request.form.get("role") or "").strip().lower()

        if not (target_id and new_role and new_role in ADMIN_LIKE_ROLES):
            flash("Geçersiz rol veya kullanıcı.", "danger")
            return redirect(url_for("club_members", club_id=club_id))
        
        if target_id == user["id"]:
            flash("Kendinizin rolünü değiştiremezsiniz.", "warning")
            return redirect(url_for("club_members", club_id=club_id))
            
        with engine.begin() as con:
            con.execute(text("""
              UPDATE club_members SET role=:r WHERE club_id=:c AND user_id=:u
            """), {"r": new_role, "c": club_id, "u": target_id})
        
        flash("Rol güncellendi.", "success")
        return redirect(url_for("club_members", club_id=club_id))

    # ===================== KULÜP GRAFİK =====================
    @app.get("/clubs/<int:club_id>/graph")
    def club_graph(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        
        is_member, is_admin = user_membership(club_id, user["id"])
        if not is_member: return abort(403)
        
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            
            # Üyeleri çek
            members = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url 
              FROM club_members m JOIN users u ON u.id=m.user_id
              WHERE m.club_id=:c
              ORDER BY u.name
            """), {"c": club_id}).mappings().all()
            
            # Kabul edilmiş bağlantıları çek
            edges = con.execute(text("""
              SELECT src_user_id, dst_user_id
              FROM graph_edges 
              WHERE club_id=:c AND status='accepted'
            """), {"c": club_id}).mappings().all()

        nodes = [{"id": m["id"], "name": m["name"], "avatar": m["avatar_url"]} for m in members]
        links = [{"source": e["src_user_id"], "target": e["dst_user_id"]} for e in edges]
        
        graph_data = json.dumps({"nodes": nodes, "links": links})

        fallback = f"""
        <a href="{url_for('club_dashboard', club_id=club_id)}">← Geri</a>
        <h2>{club['name']} Arkadaşlık Grafiği (Beta)</h2>
        <p>Grafik görünümü için D3.js benzeri bir kütüphane gerekir. Aşağıda ham veri var.</p>
        <pre>{graph_data}</pre>
        """
        return try_render("club_graph.html", user=user, club=club, graph_data=graph_data,
                          page_title=f"{club['name']} Grafiği", fallback_html=fallback)

    # ===================== BAĞLANTI İŞLEMLERİ =====================
    @app.post("/clubs/<int:club_id>/connect/request")
    def connect_request(club_id):
        user = current_user()
        if not user: return abort(401)
        
        target_id = request.form.get("target_user_id", type=int)
        if not target_id or target_id == user["id"]:
            flash("Geçersiz kullanıcı.", "danger")
            return redirect(url_for("club_dashboard", club_id=club_id))
        
        is_member, _ = user_membership(club_id, target_id)
        if not is_member:
            flash("Bağlantı isteği sadece kulüp üyelerine gönderilebilir.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))
            
        src, dst = canonical_pair(user["id"], target_id)
        
        with engine.begin() as con:
            # Önce mevcut bir edge var mı bakalım
            existing = con.execute(text("""
              SELECT id FROM graph_edges
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
            """), {"c": club_id, "s": src, "d": dst}).first()
            
            if existing:
                flash("Zaten bekleyen veya kabul edilmiş bir bağlantı isteği var.", "warning")
            else:
                con.execute(text("""
                  INSERT INTO graph_edges (club_id, src_user_id, dst_user_id, status, requested_by, created_at)
                  VALUES (:c, :s, :d, 'pending', :req, :ts)
                """), {"c": club_id, "s": src, "d": dst, "req": user["id"], "ts": now_ts()})
                flash("Bağlantı isteği gönderildi!", "success")
        
        return redirect(url_for("club_dashboard", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect/cancel")
    def connect_cancel(club_id):
        user = current_user()
        if not user: return abort(401)
        
        target_id = request.form.get("target_user_id", type=int)
        if not target_id or target_id == user["id"]:
            flash("Geçersiz kullanıcı.", "danger")
            return redirect(url_for("club_dashboard", club_id=club_id))
            
        src, dst = canonical_pair(user["id"], target_id)
        
        with engine.begin() as con:
            res = con.execute(text("""
              DELETE FROM graph_edges
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d AND requested_by=:u AND status='pending'
            """), {"c": club_id, "s": src, "d": dst, "u": user["id"]})
            
            if res.rowcount > 0:
                flash("Bağlantı isteği iptal edildi.", "success")
            else:
                flash("İptal edilecek bekleyen bir istek bulunamadı.", "warning")
        
        return redirect(url_for("club_dashboard", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect/respond")
    def connect_respond(club_id):
        user = current_user()
        if not user: return abort(401)
        
        src_id = request.form.get("src_user_id", type=int)
        dst_id = request.form.get("dst_user_id", type=int)
        action = (request.form.get("action") or "").strip().lower()
        
        if not (src_id and dst_id and action in {"accept", "decline"}):
            flash("Geçersiz işlem.", "danger")
            return redirect(url_for("club_dashboard", club_id=club_id))
            
        # Sadece dst_id, yani isteği alan kişi cevap verebilir
        if user["id"] != dst_id and user["id"] != src_id:
            return abort(403)
            
        with engine.begin() as con:
            # Durumu kontrol et ve sadece bekleyendeyse güncelle
            row = con.execute(text("""
              SELECT status, requested_by FROM graph_edges
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
            """), {"c": club_id, "s": src_id, "d": dst_id}).mappings().first()
            
            if not row or row["status"] != "pending" or row["requested_by"] == user["id"]:
                flash("Geçersiz veya süresi dolmuş bir istek.", "warning")
                return redirect(url_for("club_dashboard", club_id=club_id))
            
            new_status = "accepted" if action == "accept" else "declined"
            con.execute(text("""
              UPDATE graph_edges
              SET status=:status, responded_at=:ts
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
            """), {"status": new_status, "ts": now_ts(), "c": club_id, "s": src_id, "d": dst_id})
            
            if new_status == "accepted":
                flash("Bağlantı isteği kabul edildi!", "success")
            else:
                flash("Bağlantı isteği reddedildi.", "info")
        
        return redirect(url_for("club_dashboard", club_id=club_id))
        
    # ===================== KULÜP ANALİTİK =====================
    @app.get("/clubs/<int:club_id>/analytics")
    def club_analytics(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        
        is_member, is_admin = user_membership(club_id, user["id"])
        if not is_admin: return abort(403)
        
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            
            # Üye sayısı
            member_count = con.execute(text("SELECT COUNT(*) FROM club_members WHERE club_id=:c"), {"c": club_id}).scalar() or 0
            
            # Etkinlik & Toplantı sayıları
            event_counts = con.execute(text("""
              SELECT COALESCE(category,'event') AS category, COUNT(*) 
              FROM events WHERE club_id=:c GROUP BY category
            """), {"c": club_id}).fetchall()
            event_counts_map = {row[0]: row[1] for row in event_counts}

            # En çok check-in yapan üyeler
            top_checkins = con.execute(text("""
              SELECT u.name, COUNT(*) AS checkin_count
              FROM checkins c JOIN users u ON u.id=c.user_id
              WHERE c.event_id IN (SELECT id FROM events WHERE club_id=:c)
              GROUP BY u.name ORDER BY checkin_count DESC LIMIT 10
            """), {"c": club_id}).mappings().all()

            # En popüler etkinlikler (check-in sayısına göre)
            top_events = con.execute(text("""
              SELECT e.title, COUNT(c.user_id) AS checkin_count
              FROM events e LEFT JOIN checkins c ON e.id=c.event_id
              WHERE e.club_id=:c GROUP BY e.id ORDER BY checkin_count DESC LIMIT 10
            """), {"c": club_id}).mappings().all()
            
            # Bağlantı grafiği analizi (kabul edilenler)
            connection_stats = con.execute(text("""
              SELECT 
                COUNT(*) FILTER (WHERE status='accepted') AS accepted_count,
                COUNT(*) FILTER (WHERE status='pending') AS pending_count
              FROM graph_edges WHERE club_id=:c
            """), {"c": club_id}).mappings().first()
            
        fallback = f"""
        <a href="{url_for('club_dashboard', club_id=club_id)}">← Geri</a>
        <h2>{club['name']} Analitik Paneli</h2>
        <p>Üye Sayısı: {member_count}</p>
        <p>Etkinlik Sayıları:</p>
        <ul>
        {''.join([f"<li>{k.capitalize()}: {v}</li>" for k, v in event_counts_map.items()])}
        </ul>
        <hr>
        <h3>En Çok Katılan Üyeler</h3>
        <ul>
        {''.join([f"<li>{row['name']}: {row['checkin_count']}</li>" for row in top_checkins])}
        </ul>
        <h3>En Popüler Etkinlikler</h3>
        <ul>
        {''.join([f"<li>{row['title']}: {row['checkin_count']}</li>" for row in top_events])}
        </ul>
        <hr>
        <p>Kabul Edilen Bağlantı Sayısı: {connection_stats['accepted_count']}</p>
        <p>Bekleyen Bağlantı Sayısı: {connection_stats['pending_count']}</p>
        """
        return try_render("club_analytics.html", user=user, club=club, member_count=member_count,
                          event_counts_map=event_counts_map, top_checkins=top_checkins,
                          top_events=top_events, connection_stats=connection_stats,
                          page_title=f"{club['name']} Analitik", fallback_html=fallback)

    # ===================== GÖREVLER / NOTLAR =====================
    @app.get("/clubs/<int:club_id>/tasks")
    def club_tasks(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        is_member, is_admin = user_membership(club_id, user["id"])
        if not is_member: return abort(403)
        
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            
            tasks = con.execute(text("""
              SELECT ct.*, u.name AS assigned_user_name, u2.name AS created_by_name
              FROM club_tasks ct 
              LEFT JOIN users u ON u.id=ct.assigned_user_id
              LEFT JOIN users u2 ON u2.id=ct.created_by
              WHERE ct.club_id=:c ORDER BY ct.created_at DESC
            """), {"c": club_id}).mappings().all()

            members = con.execute(text("""
              SELECT u.id, u.name FROM club_members m JOIN users u ON u.id=m.user_id WHERE m.club_id=:c
              ORDER BY u.name
            """), {"c": club_id}).mappings().all()
            
        fallback = f"""
        <a href="{url_for('club_dashboard', club_id=club_id)}">← Geri</a>
        <h2>{club['name']} Görev Yönetimi</h2>
        {'<p>Yeni Görev Ekleme Formu</p>' if is_admin else ''}
        <ul>
        {''.join([f"<li>{t['title']} (Durum: {t['status']}, Atanan: {t['assigned_user_name'] or 'Yok'})</li>" for t in tasks])}
        </ul>
        """
        return try_render("club_tasks.html", user=user, club=club, tasks=tasks, members=members, is_admin=is_admin,
                          page_title=f"{club['name']} Görevler", fallback_html=fallback)

    @app.post("/clubs/<int:club_id>/tasks/new")
    def new_task(club_id):
        user = current_user()
        if not user or not is_admin_or_owner(club_id, user["id"]):
            return abort(403)
        
        title = request.form.get("title", "").strip()
        desc = request.form.get("description", "").strip()
        assigned_id = request.form.get("assigned_user_id", type=int)
        
        if not title:
            flash("Görev başlığı gerekli.", "danger")
            return redirect(url_for("club_tasks", club_id=club_id))
            
        with engine.begin() as con:
            con.execute(text("""
              INSERT INTO club_tasks (club_id, title, description, assigned_user_id, created_by, created_at)
              VALUES (:c, :t, :d, :a, :u, :ts)
            """), {"c": club_id, "t": title, "d": desc, "a": assigned_id, "u": user["id"], "ts": now_ts()})
        
        flash("Yeni görev eklendi!", "success")
        return redirect(url_for("club_tasks", club_id=club_id))

    @app.post("/clubs/<int:club_id>/tasks/<int:task_id>/update")
    def update_task_status(club_id, task_id):
        user = current_user()
        if not user: return abort(401)
        
        new_status = (request.form.get("status") or "").strip().lower()
        if new_status not in {"todo", "in-progress", "done", "cancelled"}:
            flash("Geçersiz durum.", "danger")
            return redirect(url_for("club_tasks", club_id=club_id))

        with engine.begin() as con:
            task = con.execute(text("""
              SELECT created_by, assigned_user_id FROM club_tasks WHERE id=:t AND club_id=:c
            """), {"t": task_id, "c": club_id}).mappings().first()
            
            if not task: abort(404)
            
            # Sadece atanan veya adminler değiştirebilir
            is_admin = is_admin_or_owner(club_id, user["id"])
            if not is_admin and user["id"] not in (task["created_by"], task["assigned_user_id"]):
                 return abort(403)
            
            con.execute(text("""
              UPDATE club_tasks SET status=:s, updated_at=:ts WHERE id=:t AND club_id=:c
            """), {"s": new_status, "ts": now_ts(), "t": task_id, "c": club_id})
        
        flash("Görev durumu güncellendi!", "success")
        return redirect(url_for("club_tasks", club_id=club_id))
        
    @app.get("/clubs/<int:club_id>/notes")
    def club_notes(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        is_member, is_admin = user_membership(club_id, user["id"])
        if not is_member: return abort(403)
        
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            
            notes = con.execute(text("""
              SELECT cn.*, u.name AS created_by_name FROM club_notes cn JOIN users u ON u.id=cn.created_by
              WHERE cn.club_id=:c ORDER BY cn.created_at DESC
            """), {"c": club_id}).mappings().all()

        fallback = f"""
        <a href="{url_for('club_dashboard', club_id=club_id)}">← Geri</a>
        <h2>{club['name']} Notları</h2>
        {'<p>Yeni Not Ekleme Formu</p>' if is_admin else ''}
        <ul>
        {''.join([f"<li>{n['title']} (Oluşturan: {n['created_by_name']})</li>" for n in notes])}
        </ul>
        """
        return try_render("club_notes.html", user=user, club=club, notes=notes, is_admin=is_admin,
                          page_title=f"{club['name']} Notlar", fallback_html=fallback)

    @app.post("/clubs/<int:club_id>/notes/new")
    def new_note(club_id):
        user = current_user()
        if not user or not is_admin_or_owner(club_id, user["id"]):
            return abort(403)
        
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        
        if not title:
            flash("Not başlığı gerekli.", "danger")
            return redirect(url_for("club_notes", club_id=club_id))
            
        with engine.begin() as con:
            con.execute(text("""
              INSERT INTO club_notes (club_id, title, body, created_by, created_at)
              VALUES (:c, :t, :b, :u, :ts)
            """), {"c": club_id, "t": title, "b": body, "u": user["id"], "ts": now_ts()})
        
        flash("Yeni not eklendi!", "success")
        return redirect(url_for("club_notes", club_id=club_id))


    # ===================== ETKİNLİK İŞLEMLERİ =====================
    @app.get("/events/<int:event_id>")
    def event_details(event_id):
        user = current_user()
        if not user: return redirect(url_for("home"))

        with engine.begin() as con:
            event = con.execute(text("""
              SELECT e.*, c.name AS club_name, c.logo_url AS club_logo, c.slug AS club_slug
              FROM events e JOIN clubs c ON c.id=e.club_id
              WHERE e.id=:e
            """), {"e": event_id}).mappings().first()
            if not event: abort(404)
            
            # Üye miyiz?
            is_member, is_admin = user_membership(event["club_id"], user["id"])
            if not is_member: return abort(403)
            
            # Check-in sayısı
            checkin_count = con.execute(text("SELECT COUNT(*) FROM checkins WHERE event_id=:e"), {"e": event_id}).scalar() or 0
            
            # Ben check-in yaptım mı?
            my_checkin = con.execute(text("SELECT * FROM checkins WHERE event_id=:e AND user_id=:u"),
                                     {"e": event_id, "u": user["id"]}).mappings().first()
            
            # En son 10 check-in
            recent_checkins = con.execute(text("""
              SELECT u.name, c.checked_at
              FROM checkins c JOIN users u ON u.id=c.user_id
              WHERE c.event_id=:e ORDER BY c.checked_at DESC LIMIT 10
            """), {"e": event_id}).mappings().all()

        fallback = f"""
        <a href="{url_for('club_dashboard', club_id=event['club_id'])}">← {event['club_name']} Kulübü</a>
        <h2>{event['title']}</h2>
        <p>Tarih: {ts2human(event['starts_at'])}</p>
        <p>Türü: {event['category'].capitalize()}</p>
        <p>Katılımcı Sayısı: {checkin_count}</p>
        {'<p><strong>Zaten katılım sağladınız!</strong></p>' if my_checkin else ''}
        <hr>
        <h3>Son Katılanlar</h3>
        <ul>
        {''.join([f"<li>{c['name']} ({ts2human(c['checked_at'])})</li>" for c in recent_checkins])}
        </ul>
        """
        return try_render("event_details.html", user=user, event=event, is_admin=is_admin,
                          checkin_count=checkin_count, my_checkin=my_checkin,
                          recent_checkins=recent_checkins, page_title=event["title"], fallback_html=fallback)

    @app.get("/events/<int:event_id>/qr")
    def event_qr(event_id):
        user = current_user()
        if not user: return abort(401)
        
        with engine.begin() as con:
            event = con.execute(text("SELECT * FROM events WHERE id=:e"), {"e": event_id}).mappings().first()
            if not event: abort(404)
            is_admin, _ = user_membership(event["club_id"], user["id"])
            if not is_admin: return abort(403)

        qr_data = url_for("qr_checkin", qr_secret=event["qr_secret"], _external=True)
        img = qrcode.make(qr_data)
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)

        return send_file(buf, mimetype='image/png')

    @app.get("/qr/<qr_secret>")
    def qr_checkin(qr_secret):
        user = current_user()
        if not user:
            flash("Giriş yapmalısınız.", "warning")
            return redirect(url_for("home"))
        
        with engine.begin() as con:
            event = con.execute(text("SELECT * FROM events WHERE qr_secret=:q"), {"q": qr_secret}).mappings().first()
            if not event:
                flash("Geçersiz QR kodu.", "danger")
                return redirect(url_for("home"))
            
            # Zaten check-in yapmış mı?
            existing_checkin = con.execute(text("""
              SELECT * FROM checkins WHERE event_id=:e AND user_id=:u
            """), {"e": event["id"], "u": user["id"]}).first()

            if existing_checkin:
                flash("Bu etkinliğe zaten katılım sağladınız.", "info")
            else:
                con.execute(text("""
                  INSERT INTO checkins (event_id, user_id, via_qr_secret, checked_at)
                  VALUES (:e, :u, :q, :ts)
                """), {"e": event["id"], "u": user["id"], "q": qr_secret, "ts": now_ts()})
                flash(f"Başarıyla check-in yapıldı! {event['title']}", "success")
        
        return redirect(url_for("event_details", event_id=event["id"]))

    # ===================== E-POSTA DOĞRULAMA =====================
    # (Demo amaçlı. Gerçek uygulamada SMTP kullanır)
    @app.get("/edu/verify/<token>")
    def verify_email_token(token):
        user = current_user()
        if not user:
            flash("Giriş yapmalısınız.", "warning")
            return redirect(url_for("home"))
        
        try:
            email = serializer.loads(token, max_age=3600)
            if not email: raise ValueError
        except Exception:
            flash("Geçersiz veya süresi dolmuş bağlantı.", "danger")
            return redirect(url_for("home"))

        if not allowed_edu(email):
            flash("E-posta adresi izinli alanlardan değil.", "danger")
            return redirect(url_for("home"))

        with engine.begin() as con:
            con.execute(text("""
              UPDATE users SET edu_email=:e, edu_verified_at=:ts WHERE id=:u
            """), {"e": email, "ts": now_ts(), "u": user["id"]})
        
        flash("E-posta adresiniz başarıyla doğrulandı!", "success")
        return redirect(url_for("profile"))


    # ===================== FİLE UPLOAD =====================
    @app.post("/upload/<upload_type>")
    def upload_file(upload_type):
        user = current_user()
        if not user: return abort(401)
        
        file = request.files.get("file")
        if not file:
            return jsonify({"success": False, "error": "Dosya gerekli."}), 400
        
        out_path = None
        try:
            if upload_type == "avatar":
                filename_base = f"avatar-{user['id']}"
                out_path = _file_to_local(file, AVATAR_DIR, filename_base)
                with engine.begin() as con:
                    con.execute(text("UPDATE users SET avatar_url=:url, avatar_cached_at=:ts WHERE id=:u"),
                                {"url": out_path, "ts": now_ts(), "u": user["id"]})
            elif upload_type == "club_banner":
                club_id = request.form.get("club_id", type=int)
                if not club_id or not user_is_owner(club_id, user["id"]):
                    return jsonify({"success": False, "error": "Yetkisiz işlem."}), 403
                
                filename_base = f"club-{club_id}-banner"
                out_path = _file_to_local(file, CLUB_DIR, filename_base)
                with engine.begin() as con:
                    con.execute(text("UPDATE clubs SET banner_url=:url WHERE id=:c"),
                                {"url": out_path, "c": club_id})
            elif upload_type == "club_logo":
                club_id = request.form.get("club_id", type=int)
                if not club_id or not user_is_owner(club_id, user["id"]):
                    return jsonify({"success": False, "error": "Yetkisiz işlem."}), 403

                filename_base = f"club-{club_id}-logo"
                out_path = _file_to_local(file, CLUB_DIR, filename_base)
                with engine.begin() as con:
                    con.execute(text("UPDATE clubs SET logo_url=:url WHERE id=:c"),
                                {"url": out_path, "c": club_id})
            elif upload_type == "event_banner":
                event_id = request.form.get("event_id", type=int)
                if not event_id:
                    return jsonify({"success": False, "error": "Etkinlik ID gerekli."}), 400
                
                with engine.begin() as con:
                    event = con.execute(text("SELECT club_id FROM events WHERE id=:e"), {"e": event_id}).mappings().first()
                    if not event or not is_admin_or_owner(event["club_id"], user["id"]):
                        return jsonify({"success": False, "error": "Yetkisiz işlem."}), 403
                    
                    filename_base = f"event-{event_id}-banner"
                    out_path = _file_to_local(file, EVENT_DIR, filename_base)
                    con.execute(text("UPDATE events SET banner_url=:url WHERE id=:e"),
                                {"url": out_path, "e": event_id})
            else:
                return jsonify({"success": False, "error": "Geçersiz yükleme türü."}), 400
                
            return jsonify({"success": True, "url": out_path}), 200

        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        except Exception as e:
            if DEBUG_TRACE: traceback.print_exc()
            return jsonify({"success": False, "error": "Yükleme hatası."}), 500
            
    # ===================== KULÜP CRUD =====================
    @app.get("/club/new")
    def new_club_form():
        user = current_user()
        if not user: return redirect(url_for("home"))
        return try_render("new_club.html", user=user, page_title="Yeni Kulüp Kur")

    @app.post("/club/new")
    def create_club():
        user = current_user()
        if not user: return abort(401)
        
        name = request.form.get("name", "").strip()
        slug = (request.form.get("slug") or "").strip()
        
        if not name or len(name) < 3:
            flash("Kulüp adı en az 3 karakter olmalı.", "danger")
            return redirect(url_for("new_club_form"))
        
        if not slug:
            slug = re.sub(r'[^a-z0-9]+', '-', name.lower())
            slug = re.sub(r'^-+|-+$', '', slug)
            if not slug:
                slug = "club-" + secrets.token_hex(4)
        
        with engine.begin() as con:
            existing_slug = con.execute(text("SELECT id FROM clubs WHERE slug=:s"), {"s": slug}).first()
            if existing_slug:
                flash("Bu URL zaten kullanımda. Başka bir tane deneyin.", "danger")
                return redirect(url_for("new_club_form"))
                
            club_id = insert_with_returning(con, engine,
                sql_sqlite="INSERT INTO clubs (name, slug, owner_user_id) VALUES (:n, :s, :o)",
                sql_pg="INSERT INTO clubs (name, slug, owner_user_id) VALUES (:n, :s, :o) RETURNING id",
                params={"n": name, "s": slug, "o": user["id"]}
            )

            # Kurucuyu direkt üye yap
            insert_ignore_or_conflict(
                con, engine,
                table="club_members",
                columns=["club_id", "user_id", "role", "joined_at"],
                values_map={"club_id": club_id, "user_id": user["id"], "role": "owner", "joined_at": now_ts()},
                conflict_cols=["club_id", "user_id"]
            )
        
        flash("Yeni kulüp başarıyla kuruldu!", "success")
        return redirect(url_for("club_dashboard", club_id=club_id))


    # ===================== EVENT CRUD =====================
    @app.get("/clubs/<int:club_id>/event/new")
    def new_event_form(club_id):
        user = current_user()
        if not user or not is_admin_or_owner(club_id, user["id"]):
            return abort(403)
        
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            
        return try_render("new_event.html", user=user, club=club, page_title="Yeni Etkinlik/Toplantı")

    @app.post("/clubs/<int:club_id>/event/new")
    def create_event(club_id):
        user = current_user()
        if not user or not is_admin_or_owner(club_id, user["id"]):
            return abort(403)
        
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "event").strip().lower()
        starts_at_str = request.form.get("starts_at", "").strip()
        
        if not title or len(title) < 3:
            flash("Etkinlik başlığı en az 3 karakter olmalı.", "danger")
            return redirect(url_for("new_event_form", club_id=club_id))
            
        try:
            starts_at = time.mktime(time.strptime(starts_at_str, "%Y-%m-%dT%H:%M")) if starts_at_str else None
        except ValueError:
            flash("Geçersiz tarih formatı.", "danger")
            return redirect(url_for("new_event_form", club_id=club_id))
            
        qr_secret = secrets.token_urlsafe(16)
        
        with engine.begin() as con:
            event_id = insert_with_returning(con, engine,
                sql_sqlite="INSERT INTO events (club_id, title, category, starts_at, qr_secret, created_by) VALUES (:c, :t, :cat, :sa, :q, :u)",
                sql_pg="INSERT INTO events (club_id, title, category, starts_at, qr_secret, created_by) VALUES (:c, :t, :cat, :sa, :q, :u) RETURNING id",
                params={"c": club_id, "t": title, "cat": category, "sa": starts_at, "q": qr_secret, "u": user["id"]}
            )
        
        flash("Yeni etkinlik başarıyla oluşturuldu!", "success")
        return redirect(url_for("event_details", event_id=event_id))

    # ===================== AUTH =====================
    @app.get("/auth/linkedin")
    def linkedin_auth():
        # TODO: LinkedIn entegrasyonu gerçeklenmeli
        # Sadece demo amaçlı basit bir login akışı
        session["uid"] = 1 # Demo user ID
        flash("Demo kullanıcı olarak giriş yapıldı!", "success")
        next_url = session.pop("next_url", None)
        return redirect(next_url or url_for("home"))
        
    @app.get("/auth/logout")
    def logout():
        session.pop("uid", None)
        flash("Çıkış yapıldı.", "info")
        return redirect(url_for("home"))
        
    @app.before_request
    def before_request():
        # Giriş gerekliyse yönlendir
        if request.path not in ["/auth/linkedin", "/auth/logout"] and "uid" not in session:
            session["next_url"] = request.full_path
            
    # ===================== ERROR HANDLING =====================
    @app.errorhandler(401)
    def unauthorized_error(e):
        flash("Bu sayfaya erişmek için giriş yapmalısınız.", "danger")
        return redirect(url_for("home"))
        
    @app.errorhandler(403)
    def forbidden_error(e):
        flash("Bu kaynağa erişim yetkiniz yok.", "danger")
        return redirect(url_for("home"))

    @app.errorhandler(404)
    def page_not_found(e):
        return try_render("404.html", page_title="Sayfa Bulunamadı",
                          fallback_html="<h2>Sayfa Bulunamadı</h2><p>Aradığınız sayfa mevcut değil.</p>"), 404
                          
    # ===================== DİĞER TEMSİLİ SAYFALAR =====================
    # Sadece demo amaçlı, db.py ile güncellenmiş hali yok.
    
    @app.get("/login")
    def login_page():
        user = current_user()
        if user: return redirect(url_for("home"))
        return try_render("login.html", page_title="Giriş Yap")
        
    @app.get("/about")
    def about():
        return try_render("about.html", page_title="Hakkında")
        
    # ===================== KULÜP SAYFALARI (statik/demo) =====================
    @app.get("/clubs/<club_slug>")
    def public_club(club_slug):
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE slug=:s"), {"s": club_slug}).mappings().first()
            if not club: abort(404)
            
            is_member, _ = user_membership(club["id"], session.get("uid"))
            
            member_count = con.execute(text("SELECT COUNT(*) FROM club_members WHERE club_id=:c"), {"c": club["id"]}).scalar()
            
            events = con.execute(text("""
              SELECT e.*, COALESCE(e.starts_at, e.created_at) AS tkey
              FROM events e WHERE e.club_id=:c ORDER BY tkey DESC LIMIT 12
            """), {"c": club["id"]}).mappings().all()

        fallback = f"""
        <div style="position:relative;border-radius:16px;overflow:hidden;border:1px solid #222">
          <div style="height:180px;background:#222 url('{club.get('banner_url') or ''}') center/cover no-repeat"></div>
          <div style="padding:16px">
            <h2 style="margin:0">{club['name']}</h2>
            <div style="opacity:.7">Üye Sayısı: {member_count}</div>
            {'<p>Zaten bu kulübe üyesiniz.</p>' if is_member else ''}
          </div>
        </div>
        """
        return try_render("public_club.html", user=current_user(), club=club, member_count=member_count,
                          is_member=is_member, events=events, page_title=club["name"],
                          fallback_html=fallback)

    @app.get("/search")
    def search_page():
        q = (request.args.get("q") or "").strip()
        results = []
        if q and len(q) > 2:
            like_q = f"%{q}%"
            with engine.begin() as con:
                users = con.execute(text("""
                  SELECT id, name, avatar_url FROM users WHERE name ILIKE :q LIMIT 10
                """), {"q": like_q}).mappings().all()
                clubs = con.execute(text("""
                  SELECT id, name, slug, banner_url FROM clubs WHERE name ILIKE :q LIMIT 10
                """), {"q": like_q}).mappings().all()
                events = con.execute(text("""
                  SELECT e.id, e.title, c.name AS club_name FROM events e JOIN clubs c ON c.id=e.club_id
                  WHERE e.title ILIKE :q LIMIT 10
                """), {"q": like_q}).mappings().all()
                
            results = {"users": users, "clubs": clubs, "events": events}
            
        return try_render("search.html", user=current_user(), q=q, results=results, page_title="Arama")
        
    # ===================== DEV RELOAD / EMAİL DEMO =====================
    # Sadece geliştirme/demo için.
    
    @app.get("/dev/reload")
    def dev_reload():
        if os.getenv("FLASK_ENV") != "development":
            return abort(404)
        print("[Dev] Uygulama yeniden yükleniyor...")
        os.execv(sys.executable, ['python'] + sys.argv)
        
    @app.get("/dev/email")
    def dev_email_test():
        if os.getenv("FLASK_ENV") != "development":
            return abort(404)
        
        email = (request.args.get("to") or "test@example.com").strip()
        token = serializer.dumps(email)
        verify_url = url_for("verify_email_token", token=token, _external=True)
        
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = os.getenv("SMTP_PORT")
        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = os.getenv("SMTP_PASS")
        
        if not all([smtp_server, smtp_port, smtp_user, smtp_pass]):
            flash("SMTP ayarları .env dosyasında eksik. E-posta gönderimi demo modunda.", "warning")
            return try_render("dev_email.html", user=current_user(), email=email, verify_url=verify_url,
                              page_title="E-posta Demo")

        msg = EmailMessage()
        msg["Subject"] = "EDU Doğrulama Bağlantınız"
        msg["From"] = f""{os.getenv("SMTP_FROM_NAME","Topluluk")}" <{smtp_user}>"
        msg["To"] = email
        msg.set_content(f"""
Merhaba,

E-posta adresinizi doğrulamak için lütfen aşağıdaki bağlantıya tıklayın:
{verify_url}

Bu bağlantı bir saat geçerlidir.

Sevgiler,
Topluluk Uygulaması Ekibi
""")
        context = ssl.create_default_context()
        try:
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            flash("E-posta başarıyla gönderildi.", "success")
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()
            flash("E-posta gönderimi başarısız oldu.", "danger")
        
        return try_render("dev_email.html", user=current_user(), email=email, verify_url=verify_url,
                          page_title="E-posta Demo")
                          
    # ===================== API =====================
    @app.get("/api/club/<int:club_id>/members")
    def api_club_members(club_id):
        is_member, _ = user_membership(club_id, session.get("uid"))
        if not is_member: return jsonify({"error": "Unauthorized"}), 403
        
        with engine.begin() as con:
            members = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, m.role
              FROM club_members m JOIN users u ON u.id=m.user_id
              WHERE m.club_id=:c
              ORDER BY u.name
            """), {"c": club_id}).mappings().all()
            
        return jsonify(list(members))
        
    @app.get("/api/club/<int:club_id>/connections")
    def api_club_connections(club_id):
        is_member, _ = user_membership(club_id, session.get("uid"))
        if not is_member: return jsonify({"error": "Unauthorized"}), 403
        
        with engine.begin() as con:
            edges = con.execute(text("""
              SELECT src_user_id, dst_user_id FROM graph_edges 
              WHERE club_id=:c AND status='accepted'
            """), {"c": club_id}).mappings().all()
            
        return jsonify(list(edges))

    @app.post("/api/club/join")
    def api_join_club():
        user = current_user()
        if not user: return jsonify({"error": "Authentication required"}), 401
        
        club_id = request.json.get("club_id", type=int)
        if not club_id: return jsonify({"error": "Club ID is required"}), 400
        
        with engine.begin() as con:
            club = con.execute(text("SELECT id FROM clubs WHERE id=:c"), {"c": club_id}).first()
            if not club: return jsonify({"error": "Club not found"}), 404

            is_member, _ = user_membership(club_id, user["id"])
            if is_member: return jsonify({"error": "Already a member"}), 409
            
            insert_ignore_or_conflict(
                con, engine,
                table="club_members",
                columns=["club_id", "user_id", "role", "joined_at"],
                values_map={"club_id": club_id, "user_id": user["id"], "role": "member", "joined_at": now_ts()},
                conflict_cols=["club_id", "user_id"]
            )
            
        return jsonify({"success": True, "message": "Joined club successfully."}), 200

    @app.post("/api/club/leave")
    def api_leave_club():
        user = current_user()
        if not user: return jsonify({"error": "Authentication required"}), 401
        
        club_id = request.json.get("club_id", type=int)
        if not club_id: return jsonify({"error": "Club ID is required"}), 400
        
        is_owner = user_is_owner(club_id, user["id"])
        if is_owner: return jsonify({"error": "Owner cannot leave a club."}), 403
        
        with engine.begin() as con:
            res = con.execute(text("DELETE FROM club_members WHERE club_id=:c AND user_id=:u"),
                              {"c": club_id, "u": user["id"]})
        
        if res.rowcount > 0:
            return jsonify({"success": True, "message": "Left club successfully."}), 200
        else:
            return jsonify({"error": "Not a member of this club."}), 404

    @app.post("/api/club/delete")
    def api_delete_club():
        user = current_user()
        if not user: return jsonify({"error": "Authentication required"}), 401
        
        club_id = request.json.get("club_id", type=int)
        if not club_id: return jsonify({"error": "Club ID is required"}), 400
        
        if not user_is_owner(club_id, user["id"]):
            return jsonify({"error": "Only the club owner can delete the club."}), 403
            
        with engine.begin() as con:
            con.execute(text("DELETE FROM club_members WHERE club_id=:c"), {"c": club_id})
            con.execute(text("DELETE FROM events WHERE club_id=:c"), {"c": club_id})
            con.execute(text("DELETE FROM graph_edges WHERE club_id=:c"), {"c": club_id})
            con.execute(text("DELETE FROM club_tasks WHERE club_id=:c"), {"c": club_id})
            con.execute(text("DELETE FROM club_notes WHERE club_id=:c"), {"c": club_id})
            con.execute(text("DELETE FROM clubs WHERE id=:c"), {"c": club_id})

        flash("Kulüp ve tüm ilişkili veriler silindi.", "success")
        return jsonify({"success": True, "message": "Club and all associated data deleted successfully."}), 200

    @app.get("/api/user/<int:user_id>/clubs")
    def api_user_clubs(user_id):
        # Sadece kendi kulüplerini görebilir
        if user_id != session.get("uid"):
            return jsonify({"error": "Unauthorized"}), 403
            
        with engine.begin() as con:
            clubs = con.execute(text("""
              SELECT c.id, c.name, c.slug, m.role
              FROM club_members m JOIN clubs c ON c.id=m.club_id
              WHERE m.user_id=:u
              ORDER BY c.name
            """), {"u": user_id}).mappings().all()
            
        return jsonify(list(clubs))

    @app.get("/api/all_clubs")
    def api_all_clubs():
        with engine.begin() as con:
            clubs = con.execute(text("SELECT id, name, slug, banner_url, created_at FROM clubs ORDER BY created_at DESC")).mappings().all()
        return jsonify(list(clubs))

    @app.post("/api/event/new")
    def api_create_event():
        user = current_user()
        if not user: return jsonify({"error": "Authentication required"}), 401
        
        club_id = request.json.get("club_id", type=int)
        title = request.json.get("title", "").strip()
        category = request.json.get("category", "event").strip().lower()
        starts_at_ts = request.json.get("starts_at_ts", type=float)

        if not club_id or not title:
            return jsonify({"error": "Club ID and title are required"}), 400
        
        if not is_admin_or_owner(club_id, user["id"]):
            return jsonify({"error": "Unauthorized"}), 403
            
        qr_secret = secrets.token_urlsafe(16)
        
        with engine.begin() as con:
            event_id = insert_with_returning(con, engine,
                sql_sqlite="INSERT INTO events (club_id, title, category, starts_at, qr_secret, created_by) VALUES (:c, :t, :cat, :sa, :q, :u)",
                sql_pg="INSERT INTO events (club_id, title, category, starts_at, qr_secret, created_by) VALUES (:c, :t, :cat, :sa, :q, :u) RETURNING id",
                params={"c": club_id, "t": title, "cat": category, "sa": starts_at_ts, "q": qr_secret, "u": user["id"]}
            )
            
        return jsonify({"success": True, "event_id": event_id}), 201

    @app.post("/api/event/checkin")
    def api_event_checkin():
        user = current_user()
        if not user: return jsonify({"error": "Authentication required"}), 401
        
        event_id = request.json.get("event_id", type=int)
        if not event_id: return jsonify({"error": "Event ID is required"}), 400
        
        with engine.begin() as con:
            event = con.execute(text("SELECT id, club_id FROM events WHERE id=:e"), {"e": event_id}).first()
            if not event: return jsonify({"error": "Event not found"}), 404
            
            is_member, _ = user_membership(event["club_id"], user["id"])
            if not is_member: return jsonify({"error": "Unauthorized"}), 403

            existing_checkin = con.execute(text("""
              SELECT id FROM checkins WHERE event_id=:e AND user_id=:u
            """), {"e": event_id, "u": user["id"]}).first()
            
            if existing_checkin:
                return jsonify({"error": "Already checked in"}), 409
            
            con.execute(text("""
              INSERT INTO checkins (event_id, user_id, checked_at) VALUES (:e, :u, :ts)
            """), {"e": event_id, "u": user["id"], "ts": now_ts()})
            
        return jsonify({"success": True, "message": "Check-in successful."}), 201

    @app.post("/api/dev/auth")
    def api_dev_auth():
        if os.getenv("FLASK_ENV") != "development": return abort(404)
        uid = request.json.get("uid", type=int)
        if uid:
            session["uid"] = uid
            return jsonify({"success": True, "uid": uid, "message": "Authenticated as dev user."})
        return jsonify({"success": False, "message": "UID is required."}), 400

    @app.post("/api/dev/clean")
    def api_dev_clean():
        if os.getenv("FLASK_ENV") != "development": return abort(404)
        with engine.begin() as con:
            con.execute(text("DELETE FROM users WHERE id > 1"))
            con.execute(text("DELETE FROM clubs WHERE id > 1"))
            con.execute(text("DELETE FROM club_members WHERE club_id > 1 OR user_id > 1"))
            con.execute(text("DELETE FROM events"))
            con.execute(text("DELETE FROM checkins"))
            con.execute(text("DELETE FROM graph_edges"))
            con.execute(text("DELETE FROM club_tasks"))
            con.execute(text("DELETE FROM club_notes"))
        flash("DB temizlendi.", "success")
        return jsonify({"success": True})
        
    @app.get("/api/dev/stats")
    def api_dev_stats():
        if os.getenv("FLASK_ENV") != "development": return abort(404)
        with engine.begin() as con:
            counts = {
                "users": con.execute(text("SELECT COUNT(*) FROM users")).scalar(),
                "clubs": con.execute(text("SELECT COUNT(*) FROM clubs")).scalar(),
                "club_members": con.execute(text("SELECT COUNT(*) FROM club_members")).scalar(),
                "events": con.execute(text("SELECT COUNT(*) FROM events")).scalar(),
                "checkins": con.execute(text("SELECT COUNT(*) FROM checkins")).scalar(),
                "graph_edges": con.execute(text("SELECT COUNT(*) FROM graph_edges")).scalar(),
                "club_tasks": con.execute(text("SELECT COUNT(*) FROM club_tasks")).scalar(),
                "club_notes": con.execute(text("SELECT COUNT(*) FROM club_notes")).scalar()
            }
        return jsonify(counts)
        
    # ---------- Sadece dev/demo amaçlı, gerçek projede kullanılmaz.
    # Bu route'lar normalde productionda olmaz.
    @app.get("/dev/sql")
    def dev_sql():
        if os.getenv("FLASK_ENV") != "development": return abort(404)
        sql = request.args.get("q")
        if not sql: return "SQL query required."
        try:
            with engine.begin() as con:
                res = con.execute(text(sql))
                return f"<pre>{res.all()}</pre>"
        except Exception as e:
            return f"Error: <pre>{e}</pre>"
    # ---------- /dev

    @app.get("/login_success")
    def login_success():
        # Dev demo amaçlı, aslında linkedin callback'e entegre olur.
        flash("Giriş başarılı!", "success")
        email = request.args.get("email")
        nxt = session.get("next_url")
        if email and allowed_edu(email):
            return redirect(url_for("verify", next=nxt) if nxt else url_for("verify"))
        return redirect(nxt or url_for("home"))

    # ===================== GLOBALS =====================
    @app.context_processor
    def inject_globals():
        return {"HOST_URL": app.config["HOST_URL"]}

    # ---------- Basit verify akışı (şablonların bağladığı) ----------
    @app.get("/verify")
    def verify():
        user = current_user()
        allowed = os.getenv("EDU_ALLOWED_DOMAINS","")
        return try_render("verify.html", user=user, allowed=allowed, page_title="EDU Doğrulama",
                          fallback_html=f"<h2>EDU Doğrulama</h2><p>İzinli alanlar: {allowed}</p>")

    @app.post("/verify/start")
    def verify_start():
        # Demo: e-posta gönderimini maketliyoruz
        email = (request.form.get("edu_email") or "").strip()
        if not email:
            flash("E-posta gerekli.", "danger"); return redirect(url_for("verify"))
        flash("Doğrulama bağlantısı gönderildi (demo).", "success")
        return redirect(url_for("home"))
        
        
 

    return app
    
# === Connections blueprint ===
# from connect_routes import bp as connections_bp
# app.register_blueprint(connections_bp)
# === /Connections blueprint ===


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
