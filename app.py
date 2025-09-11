# app.py — FULL (LinkedIn OAuth: güçlü teşhis + güvenli yönlendirme)
import os, io, time, json, secrets, traceback
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode
from flask import (
    Flask, render_template, render_template_string, request, redirect,
    url_for, session, flash, abort, send_file, jsonify
)
from jinja2 import TemplateNotFound
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text
from PIL import Image
import qrcode
import requests
from werkzeug.middleware.proxy_fix import ProxyFix

# -------------------- Genel ayarlar --------------------
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

def now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()

def ts2human(ts):
    if not ts: return "—"
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)

# -------------------- DB yardımcıları --------------------
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
    ddl = [
        f"""CREATE TABLE IF NOT EXISTS users(
          id {'SERIAL PRIMARY KEY' if is_postgres(engine) else 'INTEGER PRIMARY KEY AUTOINCREMENT'},
          linkedin_id TEXT UNIQUE,
          name TEXT,
          avatar_url TEXT,
          avatar_cached_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'},
          edu_email TEXT,
          edu_verified_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'},
          created_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'} DEFAULT ({ts_default})
        );""",
        f"""CREATE TABLE IF NOT EXISTS clubs(
          id {'SERIAL PRIMARY KEY' if is_postgres(engine) else 'INTEGER PRIMARY KEY AUTOINCREMENT'},
          name TEXT NOT NULL,
          slug TEXT UNIQUE,
          owner_user_id INTEGER NOT NULL,
          banner_url TEXT,
          logo_url TEXT,
          created_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'} DEFAULT ({ts_default})
        );""",
        f"""CREATE TABLE IF NOT EXISTS club_members(
          club_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          role TEXT NOT NULL DEFAULT 'member',
          joined_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'} DEFAULT ({ts_default}),
          PRIMARY KEY (club_id, user_id)
        );""",
        f"""CREATE TABLE IF NOT EXISTS events(
          id {'SERIAL PRIMARY KEY' if is_postgres(engine) else 'INTEGER PRIMARY KEY AUTOINCREMENT'},
          club_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          category TEXT DEFAULT 'event',
          starts_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'},
          ends_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'},
          qr_secret TEXT NOT NULL,
          banner_url TEXT,
          created_by INTEGER NOT NULL,
          created_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'} DEFAULT ({ts_default})
        );""",
        f"""CREATE TABLE IF NOT EXISTS checkins(
          event_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          checked_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'} DEFAULT ({ts_default}),
          via_qr_secret TEXT,
          PRIMARY KEY (event_id, user_id)
        );""",
        f"""CREATE TABLE IF NOT EXISTS graph_edges(
          id {'SERIAL PRIMARY KEY' if is_postgres(engine) else 'INTEGER PRIMARY KEY AUTOINCREMENT'},
          club_id INTEGER NOT NULL,
          src_user_id INTEGER NOT NULL,
          dst_user_id INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'accepted',
          requested_by INTEGER,
          responded_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'},
          created_at {'DOUBLE PRECISION' if is_postgres(engine) else 'REAL'} DEFAULT ({ts_default}),
          UNIQUE (club_id, src_user_id, dst_user_id)
        );"""
    ]
    with engine.begin() as con:
        for sql in ddl:
            con.exec_driver_sql(sql)

def ensure_columns(engine):
    try:
        with engine.begin() as con:
            # örnek genişletmeler (varsa ekler)
            pass
    except Exception:
        if DEBUG_TRACE: traceback.print_exc()

# -------------------- Görsel yardımcıları --------------------
def _is_img_filename(fname: str) -> bool:
    import os
    ext = os.path.splitext(fname or "")[1].lower()
    return ext in ALLOWED_IMG_EXT

def _resize_and_save(image_bytes: bytes, out_path: str):
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    w, h = img.size
    if max(w, h) > MAX_IMG_SIDE:
        if w >= h:
            new_w = MAX_IMG_SIDE; new_h = int(h * (MAX_IMG_SIDE / w))
        else:
            new_h = MAX_IMG_SIDE; new_w = int(w * (MAX_IMG_SIDE / h))
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

def canonical_pair(a: int, b: int):
    return (a, b) if a <= b else (b, a)

# -------------------- App Factory --------------------
def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["HOST_URL"]   = os.getenv("HOST_URL", "http://localhost:8000").rstrip("/")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = False
    app.config["MAX_CONTENT_LENGTH"]      = 12 * 1024 * 1024

    app.config["PREFERRED_URL_SCHEME"] = "https" if app.config["HOST_URL"].startswith("https://") else "http"
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

    engine = create_engine(
        DB_URL, echo=False, future=True, pool_pre_ping=True,
        pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "5")),
        pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "280")),
        connect_args={"connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "10"))} if DB_URL.startswith("postgresql") else {},
    )

    # warm-up
    attempts = int(os.getenv("DB_CONNECT_ATTEMPTS", "5")); delay = 1.0; last_err = None
    for i in range(attempts):
        try:
            with engine.connect() as conn: conn.execute(text("SELECT 1"))
            last_err = None; break
        except Exception as e:
            last_err = e
            if DEBUG_TRACE: print(f"[DB] connect attempt {i+1}/{attempts} failed: {e}")
            if i < attempts - 1:
                time.sleep(delay); delay = delay + 1 if delay < 3 else delay * 1.6
    if last_err: raise last_err

    create_schema(engine); ensure_columns(engine)
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    # --------------- Helper’lar ---------------
    ADMIN_LIKE_ROLES = {"owner","admin","officer","coordinator","manager","lead","moderator","editor"}

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

    def try_render(tpl, **ctx):
        try:
            return render_template(tpl, **ctx)
        except TemplateNotFound:
            title = ctx.get("page_title") or "Sayfa"
            body = ctx.get("fallback_html") or "<p>Şablon eksik.</p>"
            return render_template_string(f"<!doctype html><title>{title}</title><div style='padding:20px;color:#eee;background:#111;font-family:system-ui'>{body}</div>")

    app.jinja_env.filters["ts"] = ts2human

    # -------------------- Basit sayfalar --------------------
    @app.get("/")
    def home():
        user = current_user()
        return try_render("home.html", user=user, page_title="Anasayfa", fallback_html="<h2>Home</h2>")

    @app.get("/panels")
    def panels():
        user = current_user()
        if not user:
            session["next_url"] = request.url
            return redirect(url_for("li_login"))
        return try_render("panels.html", user=user, page_title="Panellerim", fallback_html="<h2>Panellerim</h2>")

    # -------------------- AUTH (LinkedIn) --------------------
    def _encode_scope(raw: str) -> str:
        if not raw: return "r_liteprofile"
        parts = []
        for token in raw.replace(",", " ").split(" "):
            t = token.strip()
            if t: parts.append(t)
        return "%20".join(parts) if parts else "r_liteprofile"

    def _is_safe_next(nxt: str) -> bool:
        if not nxt: return False
        u = urlparse(nxt)
        return (u.scheme == "" and u.netloc == "") and nxt.startswith("/")

    def _build_redirect_uri():
        base = app.config["HOST_URL"].rstrip("/")
        return f"{base}{url_for('li_callback')}"

    @app.get("/auth/linkedin/redirect_uri")
    def li_redirect_uri_debug():
        return jsonify({
            "host_url_env": app.config["HOST_URL"],
            "computed_redirect_uri": _build_redirect_uri()
        })

    @app.get("/auth/linkedin/diag")
    def li_diag():
        data = {
            "HOST_URL": app.config["HOST_URL"],
            "LINKEDIN_CLIENT_ID_set": bool(os.getenv("LINKEDIN_CLIENT_ID")),
            "LINKEDIN_CLIENT_SECRET_set": bool(os.getenv("LINKEDIN_CLIENT_SECRET")),
            "LINKEDIN_SCOPE_raw": os.getenv("LINKEDIN_SCOPE", "r_liteprofile"),
            "computed_scope": _encode_scope(os.getenv("LINKEDIN_SCOPE", "r_liteprofile")),
            "computed_redirect_uri": _build_redirect_uri(),
        }
        # secrets mask
        return jsonify(data)

    @app.get("/auth/linkedin/login")
    def li_login():
        # next sakla
        nxt = request.args.get("next")
        session["next_url"] = nxt if _is_safe_next(nxt or "") else None

        client_id = os.getenv("LINKEDIN_CLIENT_ID")
        client_secret = os.getenv("LINKEDIN_CLIENT_SECRET")  # sadece teşhis için var
        if not client_id:
            msg = "LINKEDIN_CLIENT_ID boş. Railway .env'de tanımlı mı?"
            if DEBUG_TRACE: print("[LI][ERR]", msg)
            return try_render("oauth_error.html", page_title="LinkedIn Hatası",
                              fallback_html=f"<h3>{msg}</h3> <p>.env dosyanı kontrol et.</p>")

        redirect_uri = _build_redirect_uri()
        scope = _encode_scope(os.getenv("LINKEDIN_SCOPE", "r_liteprofile"))
        state = secrets.token_urlsafe(12)
        session["li_state"] = state

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        auth_url = "https://www.linkedin.com/oauth/v2/authorization?" + urlencode(params) + f"&scope={scope}"

        # Teşhis log’u
        if DEBUG_TRACE:
            print("[LI] redirect_uri =", redirect_uri)
            print("[LI] scope        =", scope)
            print("[LI] auth_url     =", auth_url)

        # Eğer ?dry=1 verilirse, yönlendirmek yerine URL’i ekranda göster
        if request.args.get("dry") == "1":
            html = f"""
            <h2>LinkedIn OAuth (dry-run)</h2>
            <p><b>redirect_uri</b>: {redirect_uri}</p>
            <p><b>scope</b>: {scope}</p>
            <p><a href="{auth_url}" target="_blank" rel="noopener">Yetkilendirmeye git</a></p>
            """
            return render_template_string(html)

        # Normal akış: 302
        return redirect(auth_url, code=302)

    @app.get("/auth/linkedin/callback")
    def li_callback():
        err = request.args.get("error")
        if err:
            flash(f"LinkedIn hatası: {err}", "danger")
            return redirect(url_for("home"))

        code = request.args.get("code")
        state = request.args.get("state")
        if not code or not state or state != session.get("li_state"):
            flash("Geçersiz/eksik OAuth yanıtı.", "danger")
            return redirect(url_for("home"))

        client_id = os.getenv("LINKEDIN_CLIENT_ID")
        client_secret = os.getenv("LINKEDIN_CLIENT_SECRET")
        redirect_uri = _build_redirect_uri()

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
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()
            flash("Token alınamadı.", "danger")
            return redirect(url_for("home"))

        if not token:
            flash("Yetkilendirme başarısız.", "danger")
            return redirect(url_for("home"))

        # Basit profil (liteprofile)
        li_id = None; full_name = None; email = None
        try:
            headers = {"Authorization": f"Bearer {token}"}
            me = requests.get("https://api.linkedin.com/v2/me", headers=headers, timeout=20, verify=REQUESTS_VERIFY)
            me.raise_for_status()
            j = me.json()
            li_id = j.get("id")
            first = j.get("localizedFirstName") or ""
            last  = j.get("localizedLastName") or ""
            full_name = (first + " " + last).strip() or "LinkedIn Kullanıcısı"

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

        # Kullanıcı upsert (minimal)
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

        session["uid"] = uid
        session.pop("li_state", None)
        flash("Giriş başarılı.", "success")
        nxt = session.get("next_url")
        return redirect(nxt or url_for("home"))

    # -------------------- Sağlık --------------------
    @app.get("/health")
    def health(): return {"ok": True}

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

