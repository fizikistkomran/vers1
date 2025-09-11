# app.py — FULL (LinkedIn OAuth: scope %20 encode + HOST_URL-safe redirect + ProxyFix)
import os, io, time, json, math, secrets, traceback, base64, hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode
from flask import (
    Flask, render_template, render_template_string, request, redirect,
    url_for, session, flash, abort, send_file
)
from jinja2 import TemplateNotFound
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text
from PIL import Image
import qrcode
import requests
from werkzeug.middleware.proxy_fix import ProxyFix

# ------------ Config / constants ------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
UPLOAD_DIR = os.path.join(STATIC_DIR, "uploads")
AVATAR_DIR = os.path.join(UPLOAD_DIR, "avatars")
CLUB_DIR   = os.path.join(UPLOAD_DIR, "clubs")
EVENT_DIR  = os.path.join(UPLOAD_DIR, "events")
os.makedirs(AVATAR_DIR, exist_ok=True)
os.makedirs(CLUB_DIR, exist_ok=True)
os.makedirs(EVENT_DIR, exist_ok=True)

ALLOWED_IMG_EXT = {".jpg", ".jpeg", ".png", ".webp"}
MAX_IMG_SIDE = 1024
REQUESTS_VERIFY = True
DEBUG_TRACE = bool(os.getenv("DEBUG_TRACE", "0") == "1")

# ------------ time helpers ------------
def now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()

def ts2human(ts):
    if not ts: return "—"
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)

# ------------ DB helpers ------------
def is_postgres(engine) -> bool:
    try:
        return engine.url.drivername.startswith("postgresql")
    except Exception:
        return False

def insert_with_returning(con, engine, sql_sqlite, sql_pg, params):
    if is_postgres(engine):
        row = con.execute(text(sql_pg), params).fetchone()
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

def create_schema(engine):
    ts_default = "strftime('%s','now')" if not is_postgres(engine) else "EXTRACT(EPOCH FROM NOW())"
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
                    con.exec_driver_sql("ALTER TABLE events ADD COLUMN banner_url TEXT")
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
    fname = os.path.basename(file_storage.filename)
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
    app.config["HOST_URL"]   = os.getenv("HOST_URL", "http://localhost:8000").rstrip("/")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = False
    app.config["MAX_CONTENT_LENGTH"]      = 12 * 1024 * 1024  # 12MB

    # Scheme hint (proxy arkasında doğru external URL üretimi için)
    if app.config["HOST_URL"].startswith("https://"):
        app.config["PREFERRED_URL_SCHEME"] = "https"
    else:
        app.config["PREFERRED_URL_SCHEME"] = "http"

    # ProxyFix (Railway/NGINX vb.)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # --- DB ---
    DB_URL = os.getenv("DATABASE_URL", "sqlite:///enfekte.db")
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DB_URL.startswith("postgresql://") and "+psycopg2" not in DB_URL:
        DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
    if DB_URL.startswith("postgresql+psycopg2://") and "sslmode=" not in DB_URL:
        sep = "&" if "?" in DB_URL else "?"
        DB_URL = f"{DB_URL}{sep}sslmode=require"

    pool_size    = int(os.getenv("DB_POOL_SIZE", "5"))
    max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "5"))
    pool_recycle = int(os.getenv("DB_POOL_RECYCLE", "280"))

    engine = create_engine(
        DB_URL, echo=False, future=True, pool_pre_ping=True,
        pool_size=pool_size, max_overflow=max_overflow, pool_recycle=pool_recycle,
        connect_args={"connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "10"))} if DB_URL.startswith("postgresql") else {},
    )

    # warm up
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
            if DEBUG_TRACE: print(f"[DB] connect attempt {i+1}/{attempts} failed: {e}")
            if i < attempts - 1:
                time.sleep(delay)
                delay = delay + 1 if delay < 3 else delay * 1.6
    if last_err:
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
                    con, engine, "club_members",
                    ["club_id","user_id","role","joined_at"],
                    {"club_id": club_id, "user_id": user_id, "role": role_default, "joined_at": now_ts()},
                    conflict_cols=["club_id","user_id"], update_map=None
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

    # ---------- Jinja ----------
    app.jinja_env.filters["ts"] = ts2human

    def try_render(tpl, **ctx):
        try:
            return render_template(tpl, **ctx)
        except TemplateNotFound:
            title = ctx.get("page_title") or "Sayfa"
            body = ctx.get("fallback_html") or "<p>Şablon eksik.</p>"
            return render_template_string(f"<!doctype html><title>{title}</title><div style='padding:20px;color:#eee;background:#111;font-family:system-ui'>{body}</div>")

    # ===================== HOME =====================
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
              SELECT e.*, c.name AS club_name 
              FROM events e JOIN clubs c ON c.id=e.club_id
              ORDER BY COALESCE(e.starts_at, e.created_at) DESC
              LIMIT 24
            """)).mappings().all()

        return try_render("home.html", user=user, my_clubs=my_clubs, my_events=my_events, all_events=all_events,
                          page_title="Anasayfa", fallback_html="<h2>Home</h2>")

    # ===================== CLUBS =====================
    @app.get("/panels")
    def panels():
        user = current_user()
        if not user:
            session["next_url"] = request.url
            return redirect(url_for("li_login"))
        with engine.begin() as con:
            admin_clubs = con.execute(text("""
              SELECT c.*
              FROM clubs c
              JOIN club_members m ON m.club_id=c.id AND m.user_id=:u
            """), {"u": user["id"]}).mappings().all()
        return try_render("panels.html", user=user, admin_clubs=admin_clubs,
                          page_title="Panellerim", fallback_html="<h2>Panellerim</h2>")

    @app.get("/clubs/new")
    def club_new():
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        return try_render("club_new.html", user=user, page_title="Yeni Kulüp",
                          fallback_html="<h2>Yeni Kulüp</h2>")

    @app.post("/clubs/new")
    def club_new_post():
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Kulüp adı gerekli.", "danger")
            return redirect(url_for("club_new"))
        with engine.begin() as con:
            if is_postgres(engine):
                club_id = insert_with_returning(
                    con, engine, sql_sqlite="", sql_pg="""
                      INSERT INTO clubs(name, owner_user_id, created_at) VALUES (:n,:u,:t) RETURNING id
                    """, params={"n": name, "u": user["id"], "t": now_ts()}
                )
            else:
                club_id = insert_with_returning(
                    con, engine, sql_sqlite="""
                      INSERT INTO clubs(name, owner_user_id, created_at) VALUES (:n,:u,:t)
                    """, sql_pg="", params={"n": name, "u": user["id"], "t": now_ts()}
                )
            insert_ignore_or_conflict(
                con, engine, "club_members",
                ["club_id","user_id","role","joined_at"],
                {"club_id": club_id, "user_id": user["id"], "role": "owner", "joined_at": now_ts()},
                conflict_cols=["club_id","user_id"], update_map=None
            )
        flash("Kulüp oluşturuldu.", "success")
        return redirect(url_for("club_dashboard", club_id=club_id))

    @app.get("/clubs/<int:club_id>")
    def club_dashboard(club_id):
        user = current_user()
        if not user:
            session["next_url"] = request.url
            return redirect(url_for("li_login"))
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:id"), {"id": club_id}).mappings().first()
            if not club: return abort(404)
            is_member, is_admin = user_membership(club_id, user["id"])
            members = con.execute(text("""
              SELECT u.id AS user_id, u.name, u.avatar_url, m.role
              FROM club_members m JOIN users u ON u.id=m.user_id
              WHERE m.club_id=:c
              ORDER BY CASE WHEN u.id=:me THEN 0 ELSE 1 END, LOWER(u.name)
            """), {"c": club_id, "me": user["id"]}).mappings().all()
            events = con.execute(text("""
              SELECT * FROM events WHERE club_id=:c ORDER BY COALESCE(starts_at, created_at) DESC LIMIT 24
            """), {"c": club_id}).mappings().all()

        enriched = []
        for m in members:
            if m["user_id"] == user["id"]:
                status = None
            else:
                st, req_by = get_edge_status(club_id, user["id"], m["user_id"])
                if not st:
                    status = "none"
                elif st == "accepted":
                    status = "connected"
                elif st == "pending":
                    if req_by == user["id"]:
                        status = "pending_sent"
                    else:
                        status = "pending_received"
                elif st == "declined":
                    status = "declined"
                else:
                    status = st
            enriched.append({**m, "connection_status": status})

        return try_render("club_dashboard.html",
                          user=user, club=club, is_member=is_member, is_admin=is_admin,
                          members=enriched, user_id=user["id"], events=events,
                          page_title=f"{club['name']} • Kulüp",
                          fallback_html="<h2>Kulüp</h2>")

    @app.post("/clubs/<int:club_id>/banner")
    def club_upload_banner(club_id):
        user = current_user()
        if not user: return abort(401)
        if not is_admin_or_owner(club_id, user["id"]): return abort(403)
        try:
            if "banner" in request.files and request.files["banner"].filename:
                b_url = _file_to_local(request.files["banner"], os.path.join(CLUB_DIR, str(club_id)), "banner")
                with engine.begin() as con:
                    con.execute(text("UPDATE clubs SET banner_url=:b WHERE id=:id"), {"b": b_url, "id": club_id})
            if "logo" in request.files and request.files["logo"].filename:
                l_url = _file_to_local(request.files["logo"], os.path.join(CLUB_DIR, str(club_id)), "logo")
                with engine.begin() as con:
                    con.execute(text("UPDATE clubs SET logo_url=:l WHERE id=:id"), {"l": l_url, "id": club_id})
            flash("Görseller güncellendi.", "success")
        except Exception as e:
            if DEBUG_TRACE: traceback.print_exc()
            flash(f"Görsel yüklenemedi: {e}", "danger")
        return redirect(url_for("club_dashboard", club_id=club_id))

    # ===================== GRAPH =====================
    @app.get("/clubs/<int:club_id>/graph")
    def club_graph(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        if not is_admin_or_owner(club_id, user["id"]): return abort(403)
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:id"), {"id": club_id}).mappings().first()
        max_ts = now_ts()
        return try_render("community_graph.html", club=club, club_id=club_id, max_ts=max_ts,
                          page_title="Kulüp Ağı", fallback_html="<h3>Kulüp Ağı</h3>")

    @app.get("/clubs/<int:club_id>/graph.json")
    def club_graph_json(club_id):
        user = current_user()
        if not user: return abort(401)
        try:
            max_time = float(request.args.get("max_time", "1e20"))
        except Exception:
            max_time = 1e20
        show_pending = request.args.get("pending") == "1"

        with engine.begin() as con:
            nodes = con.execute(text("""
              SELECT u.id AS id, u.name AS label, u.avatar_url AS avatar
              FROM club_members m JOIN users u ON u.id=m.user_id
              WHERE m.club_id=:c
            """), {"c": club_id}).mappings().all()
            if show_pending:
                edges = con.execute(text("""
                  SELECT src_user_id AS s, dst_user_id AS d, status
                  FROM graph_edges
                  WHERE club_id=:c AND created_at <= :t
                """), {"c": club_id, "t": max_time}).mappings().all()
            else:
                edges = con.execute(text("""
                  SELECT src_user_id AS s, dst_user_id AS d, status
                  FROM graph_edges
                  WHERE club_id=:c AND status='accepted' AND created_at <= :t
                """), {"c": club_id, "t": max_time}).mappings().all()

        return {"nodes": [dict(n) for n in nodes], "edges": [dict(e) for e in edges]}

    # ===================== EVENTS =====================
    def _parse_dt_local(s):
        if not s: return None
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return None

    @app.get("/clubs/<int:club_id>/events/new")
    def event_new(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        if not is_admin_or_owner(club_id, user["id"]):
            flash("Bu kulüpte etkinlik oluşturma yetkin yok.", "danger")
            return redirect(url_for("club_dashboard", club_id=club_id))
        return try_render("event_create.html", user=user, club_id=club_id,
                          page_title="Etkinlik Oluştur", fallback_html="<h3>Etkinlik Oluştur</h3>")

    @app.post("/clubs/<int:club_id>/events/new")
    def event_new_post(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        if not is_admin_or_owner(club_id, user["id"]):
            flash("Bu kulüpte etkinlik oluşturma yetkin yok.", "danger")
            return redirect(url_for("club_dashboard", club_id=club_id))

        title = (request.form.get("title") or "").strip()
        category = (request.form.get("category") or "event").strip()
        starts_at = _parse_dt_local(request.form.get("starts_at"))
        ends_at   = _parse_dt_local(request.form.get("ends_at"))
        if not title:
            flash("Başlık gerekli.", "danger")
            return redirect(url_for("event_new", club_id=club_id))
        qr_secret = secrets.token_urlsafe(16)
        with engine.begin() as con:
            if is_postgres(engine):
                event_id = insert_with_returning(
                    con, engine, sql_sqlite="", sql_pg="""
                      INSERT INTO events (club_id, title, category, starts_at, ends_at, qr_secret, created_by, created_at)
                      VALUES (:c,:t,:cat,:s,:e,:q,:u,:now) RETURNING id
                    """,
                    params={"c": club_id, "t": title, "cat": category, "s": starts_at, "e": ends_at, "q": qr_secret, "u": user["id"], "now": now_ts()}
                )
            else:
                event_id = insert_with_returning(
                    con, engine, sql_sqlite="""
                      INSERT INTO events (club_id, title, category, starts_at, ends_at, qr_secret, created_by, created_at)
                      VALUES (:c,:t,:cat,:s,:e,:q,:u,:now)
                    """, sql_pg="",
                    params={"c": club_id, "t": title, "cat": category, "s": starts_at, "e": ends_at, "q": qr_secret, "u": user["id"], "now": now_ts()}
                )

        try:
            if "banner" in request.files and request.files["banner"].filename:
                banner_url = _file_to_local(request.files["banner"], os.path.join(EVENT_DIR, str(event_id)), "banner")
                with engine.begin() as con:
                    con.execute(text("UPDATE events SET banner_url=:b WHERE id=:id"), {"b": banner_url, "id": event_id})
        except Exception as e:
            if DEBUG_TRACE: traceback.print_exc()
            flash(f"Banner yüklemede sorun: {e}", "warning")

        flash("Etkinlik oluşturuldu.", "success")
        return redirect(url_for("event_analytics", event_id=event_id))

    @app.get("/events/<int:event_id>/analytics")
    def event_analytics(event_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        with engine.begin() as con:
            ev = con.execute(text("""
              SELECT e.*, c.name AS club_name, c.id AS club_id FROM events e JOIN clubs c ON c.id=e.club_id
              WHERE e.id=:id
            """), {"id": event_id}).mappings().first()
            if not ev: return abort(404)

            attendees = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, u.edu_email, ch.checked_at
              FROM checkins ch 
              JOIN users u ON u.id=ch.user_id
              WHERE ch.event_id=:e
              ORDER BY ch.checked_at ASC
            """), {"e": event_id}).mappings().all()

            total_att = len(attendees)
            member_count = con.execute(text("""
              SELECT COUNT(*) FROM club_members WHERE club_id=:c
            """), {"c": ev["club_id"]}).scalar() or 0
            att_rate = (total_att*100.0/member_count) if member_count else 0.0
            edu_verified_count = sum(1 for a in attendees if a.get("edu_email"))
            cont = con.execute(text("""
              SELECT COUNT(DISTINCT ch2.user_id) 
              FROM events e2 
              JOIN checkins ch2 ON ch2.event_id=e2.id
              WHERE e2.club_id=:c AND e2.id!=:eid AND COALESCE(e2.starts_at,e2.created_at) > COALESCE((SELECT starts_at FROM events WHERE id=:eid), (SELECT created_at FROM events WHERE id=:eid))
            """), {"c": ev["club_id"], "eid": event_id}).scalar() or 0
            continued = cont
            cont_rate = (continued*100.0/total_att) if total_att else 0.0

        return try_render("event_analytics.html",
                          user=user, event=ev, attendees=attendees,
                          total_att=total_att, member_count=member_count, att_rate=att_rate,
                          edu_verified_count=edu_verified_count, continued=continued, cont_rate=cont_rate,
                          page_title=f"{ev['title']} • Analiz", fallback_html="<h3>Etkinlik Analiz</h3>")

    @app.get("/join")
    def join():
        e = request.args.get("e", type=int)
        q = request.args.get("q", type=str)
        if not e or not q:
            flash("Etkinlik bilgisi eksik.", "danger")
            return redirect(url_for("home"))
        user = current_user()
        if not user:
            session["next_url"] = request.url
            return redirect(url_for("li_login"))
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": e}).mappings().first()
            if not ev:
                flash("Etkinlik bulunamadı.", "danger")
                return redirect(url_for("home"))
            if ev["qr_secret"] != q:
                flash("Geçersiz QR.", "danger")
                return redirect(url_for("home"))
            ensure_member(ev["club_id"], user["id"])
            insert_ignore_or_conflict(
                con, engine, "checkins",
                ["event_id","user_id","checked_at","via_qr_secret"],
                {"event_id": e, "user_id": user["id"], "checked_at": now_ts(), "via_qr_secret": q},
                conflict_cols=["event_id","user_id"], update_map=None
            )
        flash("Yoklamaya eklendin. Hoş geldin! 👋", "success")
        return redirect(url_for("event_analytics", event_id=e))

    @app.get("/events/<int:event_id>/live")
    def event_live(event_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev: return abort(404)
            club = con.execute(text("SELECT * FROM clubs WHERE id=:id"), {"id": ev["club_id"]}).mappings().first()
            cnt = con.execute(text("SELECT COUNT(*) FROM checkins WHERE event_id=:e"), {"e": event_id}).scalar() or 0
        join_url = f"{request.host_url.strip('/')}/join?e={event_id}&q={ev['qr_secret']}"
        return try_render("event_live_qr.html", user=user, event=ev, club=club, count=cnt, join_url=join_url,
                          page_title="Canlı QR", fallback_html=f"<p>Yoklama: {cnt}</p>")

    @app.get("/events/<int:event_id>/qr.png")
    def event_qr_png(event_id):
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev: return abort(404)
        join_url = f"{request.host_url.strip('/')}/join?e={event_id}&q={ev['qr_secret']}"
        img = qrcode.make(join_url)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")

    # ===================== CONNECTIONS =====================
    @app.post("/connect/request/<int:uid>")
    def connect_request(uid):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        if uid == user["id"]:
            flash("Kendinle bağlantı olmaz 🤝", "warning"); return redirect(request.referrer or url_for("home"))

        with engine.begin() as con:
            mutual = con.execute(text("""
              SELECT c1.club_id
              FROM club_members c1
              JOIN club_members c2 ON c2.club_id=c1.club_id AND c2.user_id=:other
              WHERE c1.user_id=:me
              ORDER BY c1.joined_at ASC
              LIMIT 1
            """), {"me": user["id"], "other": uid}).first()
        if not mutual:
            flash("Ortak olduğunuz bir kulüp yok.", "danger")
            return redirect(request.referrer or url_for("profile", uid=uid))

        club_id = mutual[0]
        s, d = canonical_pair(user["id"], uid)
        with engine.begin() as con:
            row = con.execute(text("""
              SELECT id, status, requested_by FROM graph_edges
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
            """), {"c": club_id, "s": s, "d": d}).mappings().first()
            if row:
                if row["status"] == "accepted":
                    flash("Zaten bağlısınız.", "info")
                elif row["status"] == "pending":
                    if row["requested_by"] == user["id"]:
                        flash("İstek zaten gönderilmiş.", "info")
                    else:
                        con.execute(text("""
                          UPDATE graph_edges SET status='accepted', responded_at=:t WHERE id=:id
                        """), {"t": now_ts(), "id": row["id"]})
                        flash("Bağlantı kabul edildi 🎉", "success")
                elif row["status"] == "declined":
                    con.execute(text("""
                      UPDATE graph_edges SET status='pending', requested_by=:u, responded_at=NULL WHERE id=:id
                    """), {"u": user["id"], "id": row["id"]})
                    flash("Bağlantı isteği tekrar gönderildi.", "success")
            else:
                insert_ignore_or_conflict(
                    con, engine, "graph_edges",
                    ["club_id","src_user_id","dst_user_id","status","requested_by","created_at"],
                    {"club_id": club_id, "src_user_id": s, "dst_user_id": d,
                     "status": "pending", "requested_by": user["id"], "created_at": now_ts()},
                    conflict_cols=["club_id","src_user_id","dst_user_id"], update_map=None
                )
                flash("Bağlantı isteği gönderildi.", "success")
        return redirect(request.referrer or url_for("profile", uid=uid))

    # ===================== PROFILE =====================
    @app.get("/profile")
    def profile():
        user = current_user()
        if not user:
            session["next_url"] = request.url
            return redirect(url_for("li_login"))
        view_uid = request.args.get("uid", type=int) or user["id"]
        with engine.begin() as con:
            profile_user = con.execute(text("SELECT * FROM users WHERE id=:id"), {"id": view_uid}).mappings().first()
            if not profile_user: return abort(404)
            memberships = con.execute(text("""
              SELECT c.*, m.role FROM clubs c JOIN club_members m ON m.club_id=c.id
              WHERE m.user_id=:u ORDER BY c.created_at DESC
            """), {"u": view_uid}).mappings().all()

        connection_status = None
        if view_uid != user["id"]:
            with engine.begin() as con:
                rows = con.execute(text("""
                  SELECT ge.status, ge.requested_by
                  FROM graph_edges ge
                  JOIN club_members m1 ON m1.club_id=ge.club_id AND m1.user_id=:me
                  JOIN club_members m2 ON m2.club_id=ge.club_id AND m2.user_id=:other
                  WHERE (ge.src_user_id=:s AND ge.dst_user_id=:d) OR (ge.src_user_id=:d AND ge.dst_user_id=:s)
                """), {"me": user["id"], "other": view_uid, "s": min(user["id"], view_uid), "d": max(user["id"], view_uid)}).mappings().all()
            st = None; req_by = None
            for r in rows:
                if r["status"] == "accepted": st, req_by = "accepted", r["requested_by"]; break
                if r["status"] == "pending": st, req_by = "pending", r["requested_by"]
            if not st:
                connection_status = "none"
            elif st == "accepted":
                connection_status = "connected"
            elif st == "pending":
                connection_status = "pending_sent" if req_by == user["id"] else "pending_received"

        return try_render("profile.html",
                          user=user, user_id=user["id"],
                          profile_user=profile_user, memberships=memberships,
                          connection_status=connection_status or "none",
                          page_title=f"{profile_user['name']} • Profil",
                          fallback_html=f"<h2>Profil: {profile_user['name']}</h2>")

    @app.get("/profile/edit")
    def profile_edit():
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        return try_render("profile_edit.html", user=user, page_title="Profil Düzenle",
                          fallback_html="<h3>Profil Düzenle</h3>")

    @app.post("/profile/edit")
    def profile_edit_post():
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        name = (request.form.get("name") or "").strip()
        if name:
            with engine.begin() as con:
                con.execute(text("UPDATE users SET name=:n WHERE id=:id"), {"n": name, "id": user["id"]})
        try:
            if "avatar" in request.files and request.files["avatar"].filename:
                path = _file_to_local(request.files["avatar"], AVATAR_DIR, str(user["id"]))
                with engine.begin() as con:
                    con.execute(text("UPDATE users SET avatar_url=:a, avatar_cached_at=:t WHERE id=:id"),
                                {"a": path, "t": now_ts(), "id": user["id"]})
        except Exception as e:
            if DEBUG_TRACE: traceback.print_exc()
            flash(f"Avatar yüklemede sorun: {e}", "warning")
        flash("Profil güncellendi.", "success")
        return redirect(url_for("profile"))

    # ===================== AUTH (LinkedIn OAuth) =====================
    def _build_redirect_uri():
        # HOST_URL (env) + relative path (proxy/https kafa karışıklığını önler)
        base = app.config["HOST_URL"].rstrip("/")
        return f"{base}{url_for('li_callback')}"

    def _is_safe_next(nxt: str) -> bool:
        if not nxt: return False
        u = urlparse(nxt)
        return (u.scheme == "" and u.netloc == "") and nxt.startswith("/")

    def _encode_scope(raw: str) -> str:
        # Accept: "a b c" or "a,b,c" → "a%20b%20c"
        if not raw: return "r_liteprofile"
        parts = []
        for token in raw.replace(",", " ").split(" "):
            t = token.strip()
            if t: parts.append(t)
        return "%20".join(parts) if parts else "r_liteprofile"

    @app.get("/auth/linkedin/login")
    def li_login():
        # next param sakla (internal path olmalı)
        nxt = request.args.get("next")
        session["next_url"] = nxt if _is_safe_next(nxt or "") else None

        client_id = os.getenv("LINKEDIN_CLIENT_ID")
        scope_raw = os.getenv("LINKEDIN_SCOPE", "r_liteprofile")
        scope = _encode_scope(scope_raw)

        # CSRF için state
        state = secrets.token_urlsafe(12)
        session["li_state"] = state

        redirect_uri = _build_redirect_uri()
        # scope'u kendimiz encode ettik, diğer paramları urlencode edelim
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        auth_url = "https://www.linkedin.com/oauth/v2/authorization?" + urlencode(params) + f"&scope={scope}"
        return redirect(auth_url)

    @app.get("/auth/linkedin/callback")
    def li_callback():
        err = request.args.get("error")
        if err:
            flash(f"LinkedIn hatası: {err}", "danger")
            return redirect(url_for("home"))

        code = request.args.get("code")
        state = request.args.get("state")
        if not code or not state or state != session.get("li_state"):
            flash("Geçersiz veya eksik OAuth yanıtı.", "danger")
            return redirect(url_for("home"))

        client_id = os.getenv("LINKEDIN_CLIENT_ID")
        client_secret = os.getenv("LINKEDIN_CLIENT_SECRET")
        redirect_uri = _build_redirect_uri()

        # Access token al
        token = None
        try:
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            }
            tok = requests.post("https://www.linkedin.com/oauth/v2/accessToken", data=data, timeout=20, verify=REQUESTS_VERIFY)
            tok.raise_for_status()
            token = tok.json().get("access_token")
        except Exception as e:
            if DEBUG_TRACE: traceback.print_exc()
            flash("Token alınamadı.", "danger")
            return redirect(url_for("home"))

        if not token:
            flash("Yetkilendirme başarısız.", "danger")
            return redirect(url_for("home"))

        # Profil & e-posta
        li_id = None
        full_name = None
        email = None
        avatar_url_final = None
        try:
            headers = {"Authorization": f"Bearer {token}"}

            me = requests.get("https://api.linkedin.com/v2/me", headers=headers, timeout=20, verify=REQUESTS_VERIFY)
            me.raise_for_status()
            j = me.json()
            li_id = j.get("id")
            first = j.get("localizedFirstName") or ""
            last  = j.get("localizedLastName") or ""
            full_name = (first + " " + last).strip() or "LinkedIn Kullanıcısı"

            # Eğer scope'ta r_emailaddress yoksa bu request boş dönebilir — sorun değil.
            em = requests.get(
                "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
                headers=headers, timeout=20, verify=REQUESTS_VERIFY
            )
            if em.ok:
                ej = em.json()
                els = ej.get("elements") or []
                if els:
                    email = ((els[0] or {}).get("handle~") or {}).get("emailAddress")

        except Exception:
            if DEBUG_TRACE: traceback.print_exc()

        if not li_id:
            flash("Profil bilgisi alınamadı.", "danger")
            return redirect(url_for("home"))

        # Kullanıcıyı oluştur/güncelle
        with engine.begin() as con:
            row = con.execute(text("SELECT id FROM users WHERE linkedin_id=:lid"), {"lid": li_id}).first()
            if row:
                uid = row[0]
                con.execute(text("UPDATE users SET name=:n WHERE id=:id"), {"n": full_name, "id": uid})
            else:
                if is_postgres(engine):
                    uid = insert_with_returning(
                        con, engine, sql_sqlite="", sql_pg="""
                        INSERT INTO users (linkedin_id, name, avatar_url, edu_email)
                        VALUES (:lid, :n, NULL, :e) RETURNING id
                        """, params={"lid": li_id, "n": full_name, "e": email}
                    )
                else:
                    uid = insert_with_returning(
                        con, engine, sql_sqlite="""
                        INSERT INTO users (linkedin_id, name, avatar_url, edu_email)
                        VALUES (:lid, :n, NULL, :e)
                        """, sql_pg="", params={"lid": li_id, "n": full_name, "e": email}
                    )

        if avatar_url_final:
            with engine.begin() as con:
                con.execute(text("UPDATE users SET avatar_url=:a, avatar_cached_at=:t WHERE id=:id"),
                            {"a": avatar_url_final, "t": now_ts(), "id": uid})

        session["uid"] = uid
        session.pop("li_state", None)
        flash("Giriş başarılı.", "success")

        nxt = session.get("next_url")
        if nxt and not _is_safe_next(nxt):  # güvenlik
            nxt = None
        if email and allowed_edu(email):
            return redirect(url_for("verify", next=nxt) if nxt else url_for("verify"))
        return redirect(nxt or url_for("home"))

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

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    @app.get("/health")
    def health():
        return {"ok": True}

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

