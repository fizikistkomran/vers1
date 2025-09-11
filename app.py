import os, io, csv, json, time, traceback, secrets
from urllib.parse import urlencode, quote
import requests, certifi, qrcode
from PIL import Image
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import (
    Flask, render_template, render_template_string, redirect, url_for, session,
    request, flash, send_file, abort, Response
)
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text
from jinja2 import TemplateNotFound

# ---------------- ENV ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOTENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(DOTENV_PATH)

DEBUG_TRACE     = os.getenv("DEBUG_TRACE", "0") == "1"
VERIFY_SSL      = os.getenv("VERIFY_SSL", "true").lower() == "true"
REQUESTS_VERIFY = (certifi.where() if VERIFY_SSL else False)

UPLOAD_ROOT = os.path.join(BASE_DIR, "static", "uploads")
AVATAR_DIR  = os.path.join(UPLOAD_ROOT, "avatars")
CLUB_DIR    = os.path.join(UPLOAD_ROOT, "clubs")
EVENT_DIR   = os.path.join(UPLOAD_ROOT, "events")
for p in (UPLOAD_ROOT, AVATAR_DIR, CLUB_DIR, EVENT_DIR):
    os.makedirs(p, exist_ok=True)

ALLOWED_IMG_EXT = {".jpg", ".jpeg", ".png", ".webp"}
MAX_IMG_SIDE = 1600

def now_ts() -> float: return float(time.time())
def ts2human(ts):
    if not ts: return "-"
    try: return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))
    except Exception: return "-"

# ---------------- DB helpers ----------------
def is_postgres(engine) -> bool: return engine.dialect.name in ("postgresql", "postgres")
def current_ts_sql(engine) -> str: return "EXTRACT(EPOCH FROM NOW())" if is_postgres(engine) else "strftime('%s','now')"

def insert_with_returning(con, engine, sql_sqlite, sql_pg, params):
    if is_postgres(engine) and sql_pg:
        return con.execute(text(sql_pg), params).first()[0]
    con.execute(text(sql_sqlite), params)
    return con.execute(text("SELECT last_insert_rowid()")).scalar()

def create_schema(engine):
    ts_default = current_ts_sql(engine)
    if is_postgres(engine):
        ddl = [
            f"""CREATE TABLE IF NOT EXISTS users(
                id SERIAL PRIMARY KEY,
                linkedin_id TEXT UNIQUE,
                name TEXT,
                avatar_url TEXT,
                avatar_cached_at DOUBLE PRECISION,
                edu_email TEXT,
                edu_verified_at DOUBLE PRECISION,
                created_at DOUBLE PRECISION DEFAULT ({ts_default})
            );""",
            f"""CREATE TABLE IF NOT EXISTS clubs(
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT UNIQUE,
                owner_user_id INTEGER NOT NULL,
                banner_url TEXT,
                logo_url TEXT,
                created_at DOUBLE PRECISION DEFAULT ({ts_default})
            );""",
            f"""CREATE TABLE IF NOT EXISTS club_members(
                club_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at DOUBLE PRECISION DEFAULT ({ts_default}),
                PRIMARY KEY (club_id, user_id)
            );""",
            f"""CREATE TABLE IF NOT EXISTS events(
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
            f"""CREATE TABLE IF NOT EXISTS checkins(
                event_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                checked_at DOUBLE PRECISION DEFAULT ({ts_default}),
                via_qr_secret TEXT,
                PRIMARY KEY (event_id, user_id)
            );""",
            f"""CREATE TABLE IF NOT EXISTS graph_edges(
                id SERIAL PRIMARY KEY,
                club_id INTEGER NOT NULL,
                src_user_id INTEGER NOT NULL,
                dst_user_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'accepted',
                created_at DOUBLE PRECISION DEFAULT ({ts_default}),
                UNIQUE (club_id, src_user_id, dst_user_id)
            );"""
        ]
    else:
        ddl = [
            f"""CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                linkedin_id TEXT UNIQUE,
                name TEXT,
                avatar_url TEXT,
                avatar_cached_at REAL,
                edu_email TEXT,
                edu_verified_at REAL,
                created_at REAL DEFAULT ({ts_default})
            );""",
            f"""CREATE TABLE IF NOT EXISTS clubs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                slug TEXT UNIQUE,
                owner_user_id INTEGER NOT NULL,
                banner_url TEXT,
                logo_url TEXT,
                created_at REAL DEFAULT ({ts_default})
            );""",
            f"""CREATE TABLE IF NOT EXISTS club_members(
                club_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at REAL DEFAULT ({ts_default}),
                PRIMARY KEY (club_id, user_id)
            );""",
            f"""CREATE TABLE IF NOT EXISTS events(
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
            f"""CREATE TABLE IF NOT EXISTS checkins(
                event_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                checked_at REAL DEFAULT ({ts_default}),
                via_qr_secret TEXT,
                PRIMARY KEY (event_id, user_id)
            );""",
            f"""CREATE TABLE IF NOT EXISTS graph_edges(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                club_id INTEGER NOT NULL,
                src_user_id INTEGER NOT NULL,
                dst_user_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'accepted',
                created_at REAL DEFAULT ({ts_default}),
                UNIQUE (club_id, src_user_id, dst_user_id)
            );"""
        ]
    with engine.begin() as con:
        for sql in ddl: con.exec_driver_sql(sql)

def ensure_columns(engine):
    try:
        with engine.begin() as con:
            if not is_postgres(engine):
                def has_col(table, col):
                    rows = con.execute(text(f"PRAGMA table_info({table})")).fetchall()
                    return col in [r[1] for r in rows]
                if not has_col("users", "avatar_cached_at"):
                    con.exec_driver_sql("ALTER TABLE users ADD COLUMN avatar_cached_at REAL")
                if not has_col("users", "edu_email"):
                    con.exec_driver_sql("ALTER TABLE users ADD COLUMN edu_email TEXT")
                for t,c in [("clubs","banner_url"),("clubs","logo_url"),("events","banner_url"),("events","category")]:
                    if not has_col(t, c): con.exec_driver_sql(f"ALTER TABLE {t} ADD COLUMN {c} TEXT")
            else:
                con.exec_driver_sql("ALTER TABLE users  ADD COLUMN IF NOT EXISTS avatar_cached_at DOUBLE PRECISION")
                con.exec_driver_sql("ALTER TABLE users  ADD COLUMN IF NOT EXISTS edu_email TEXT")
                con.exec_driver_sql("ALTER TABLE clubs  ADD COLUMN IF NOT EXISTS banner_url TEXT")
                con.exec_driver_sql("ALTER TABLE clubs  ADD COLUMN IF NOT EXISTS logo_url TEXT")
                con.exec_driver_sql("ALTER TABLE events ADD COLUMN IF NOT EXISTS banner_url TEXT")
                con.exec_driver_sql("ALTER TABLE events ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'event'")
    except Exception:
        if DEBUG_TRACE: traceback.print_exc()

# ---------------- Image helpers ----------------
def _is_img_filename(fname: str) -> bool:
    return os.path.splitext(fname or "")[1].lower() in ALLOWED_IMG_EXT

def _resize_and_save(image_bytes: bytes, out_path: str):
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    w, h = img.size
    if max(w, h) > MAX_IMG_SIDE:
        if w >= h: new_w, new_h = MAX_IMG_SIDE, int(h * (MAX_IMG_SIDE / w))
        else:      new_h, new_w = MAX_IMG_SIDE, int(w * (MAX_IMG_SIDE / h))
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
        _resize_and_save(r.content, out_path); return True
    except Exception:
        if DEBUG_TRACE: traceback.print_exc()
        return False

def _file_to_local(file_storage, out_dir: str, filename_base: str) -> str:
    if not file_storage or not getattr(file_storage, "filename", None):
        return None
    fname = secure_filename(file_storage.filename)
    if not _is_img_filename(fname): raise ValueError("Desteklenmeyen görsel türü.")
    raw = file_storage.read()
    if len(raw) > 10 * 1024 * 1024: raise ValueError("Dosya çok büyük (10MB üstü).")
    out_path = os.path.join(out_dir, f"{filename_base}.jpg")
    _resize_and_save(raw, out_path)
    web_rel = out_path.split(os.path.join(BASE_DIR, "static"))[-1].replace("\\","/")
    return "/static" + web_rel

# ---------------- App factory ----------------
def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["HOST_URL"]   = os.getenv("HOST_URL", "http://localhost:8000").rstrip("/")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = False
    app.config["MAX_CONTENT_LENGTH"]      = 12 * 1024 * 1024
    app.config["PREFERRED_URL_SCHEME"]    = "https" if app.config["HOST_URL"].startswith("https://") else "http"
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # DB
    DB_URL = os.getenv("DATABASE_URL", "sqlite:///enfekte.db")
    if DB_URL.startswith("postgres://"): DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DB_URL.startswith("postgresql://") and "+psycopg2" not in DB_URL:
        DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
    if DB_URL.startswith("postgresql+psycopg2://") and "sslmode=" not in DB_URL:
        sep = "&" if "?" in DB_URL else "?"
        DB_URL = f"{DB_URL}{sep}sslmode=require"

    engine = create_engine(DB_URL, echo=False, future=True, pool_pre_ping=True)
    create_schema(engine); ensure_columns(engine)
    URLSafeTimedSerializer(app.config["SECRET_KEY"])

    ADMIN_LIKE_ROLES = set([r.strip().lower() for r in os.getenv(
        "ADMIN_LIKE_ROLES",
        "owner,admin,officer,coordinator,manager,lead,moderator,editor"
    ).split(",") if r.strip()]) or {"owner","admin"}

    # --- helpers
    def current_user():
        uid = session.get("uid")
        if not uid: return None
        with engine.begin() as con:
            row = con.execute(text("SELECT * FROM users WHERE id=:id"), {"id": uid}).mappings().first()
            return dict(row) if row else None

    def allowed_edu(email: str) -> bool:
        if not email: return False
        domains = [d.strip().lower() for d in os.getenv("EDU_ALLOWED_DOMAINS","").split(",") if d.strip()]
        return any(email.lower().endswith("@" + d) for d in domains)

    def is_admin_or_owner(club_id: int, user_id: int) -> bool:
        with engine.begin() as con:
            role_row = con.execute(text("SELECT role FROM club_members WHERE club_id=:c AND user_id=:u"),
                                   {"c": club_id, "u": user_id}).first()
            if role_row:
                role = (role_row[0] or "").lower()
                if role in ADMIN_LIKE_ROLES or role != "member": return True
            club = con.execute(text("SELECT owner_user_id FROM clubs WHERE id=:c"), {"c": club_id}).first()
            return bool(club and club[0] == user_id)

    def user_membership(club_id: int, user_id: int):
        with engine.begin() as con:
            row = con.execute(text("SELECT role FROM club_members WHERE club_id=:c AND user_id=:u"),
                              {"c": club_id, "u": user_id}).first()
        is_member = row is not None
        is_admin = bool(row and ((row[0] or "").lower() in ADMIN_LIKE_ROLES or (row[0] or "").lower() != "member"))
        return is_member, is_admin

    app.jinja_env.filters["ts"] = ts2human

    def try_render(tpl, **ctx):
        try:
            return render_template(tpl, **ctx)
        except TemplateNotFound:
            title = ctx.get("page_title") or "Sayfa"
            body = ctx.get("fallback_html") or "<p>Şablon eksik.</p>"
            return render_template_string(f"<!doctype html><title>{title}</title><div style='padding:20px;color:#eee;background:#111;font-family:system-ui'>{body}</div>")

    # ---------------- routes ----------------
    @app.get("/health")
    def health(): return {"ok": True}

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    # ---- LinkedIn OAuth (aynı akış; kısaltılmış içerik) ----
    @app.get("/auth/linkedin/login")
    def li_login():
        nxt = request.args.get("next")
        if nxt: session["next_url"] = nxt
        client_id = os.getenv("LINKEDIN_CLIENT_ID")
        if not client_id:
            flash("LinkedIn client_id tanımlı değil.", "danger"); return redirect(url_for("home"))
        host_url = (os.getenv("HOST_URL") or app.config.get("HOST_URL") or "").rstrip("/")
        redirect_uri = host_url + url_for("li_callback")
        state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
        session["oauth_state"] = state; session["oidc_nonce"] = nonce
        scope = " ".join((os.getenv("LINKEDIN_SCOPE","r_liteprofile").strip()).split())
        session["oauth_scope"] = scope
        params = {"response_type":"code","client_id":client_id,"redirect_uri":redirect_uri,"scope":scope,"state":state}
        if "openid" in scope.split(): params["nonce"] = nonce
        return redirect("https://www.linkedin.com/oauth/v2/authorization?" + urlencode(params))

    @app.get("/auth/linkedin/callback")
    def li_callback():
        if request.args.get("error"):
            flash(f"LinkedIn yetkilendirme hatası: {request.args.get('error_description','error')}", "danger")
            return redirect(url_for("home"))
        state = request.args.get("state")
        if not state or state != session.get("oauth_state"):
            flash("CSRF uyarısı: state uyuşmuyor.", "danger"); return redirect(url_for("home"))
        code = request.args.get("code")
        if not code: flash("Yetkilendirme kodu alınamadı.", "danger"); return redirect(url_for("home"))

        token_url = "https://www.linkedin.com/oauth/v2/accessToken"
        host_url = (os.getenv("HOST_URL") or app.config.get("HOST_URL") or "").rstrip("/")
        redirect_uri = host_url + url_for("li_callback")
        data = {"grant_type":"authorization_code","code":code,"redirect_uri":redirect_uri,
                "client_id":os.getenv("LINKEDIN_CLIENT_ID"),"client_secret":os.getenv("LINKEDIN_CLIENT_SECRET")}
        try:
            resp = requests.post(token_url, data=data, headers={"Content-Type":"application/x-www-form-urlencoded"},
                                 timeout=20, verify=REQUESTS_VERIFY)
            if resp.status_code != 200:
                flash("LinkedIn access token alınamadı.", "danger"); return redirect(url_for("home"))
            tok = resp.json(); access_token = tok.get("access_token")
            if not access_token: flash("Access token bulunamadı.", "danger"); return redirect(url_for("home"))
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()
            flash("Token değişiminde hata oluştu.", "danger"); return redirect(url_for("home"))

        headers = {"Authorization": f"Bearer {access_token}", "X-Restli-Protocol-Version": "2.0.0"}
        requested_scope = (session.get("oauth_scope") or os.getenv("LINKEDIN_SCOPE","r_liteprofile")).split()
        sub = name = email = avatar_remote = None

        if "openid" in requested_scope:
            try:
                uresp = requests.get("https://api.linkedin.com/v2/userinfo", headers=headers, timeout=15, verify=REQUESTS_VERIFY)
                if uresp.status_code == 200:
                    uj = uresp.json()
                    sub = uj.get("sub")
                    name = uj.get("name") or (uj.get("given_name","")+" "+uj.get("family_name","")).strip() or "LinkedIn User"
                    email = uj.get("email") or uj.get("emailAddress")
                    avatar_remote = uj.get("picture")
            except Exception:
                if DEBUG_TRACE: traceback.print_exc()

        try:
            if not sub and "r_liteprofile" in requested_scope:
                me = requests.get(
                    "https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))",
                    headers=headers, timeout=15, verify=REQUESTS_VERIFY
                )
                if me.status_code == 200:
                    mp = me.json()
                    sub = mp.get("id")
                    first, last = mp.get("localizedFirstName",""), mp.get("localizedLastName","")
                    name = (first+" "+last).strip() or name or "LinkedIn User"
                    try:
                        pics = mp["profilePicture"]["displayImage~"]["elements"]
                        if pics: avatar_remote = pics[-1]["identifiers"][0]["identifier"]
                    except Exception: pass

            if not email and "r_emailaddress" in requested_scope:
                mail = requests.get("https://www.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
                                    headers=headers, timeout=15, verify=REQUESTS_VERIFY)
                if mail.status_code == 200:
                    try: email = mail.json()["elements"][0]["handle~"]["emailAddress"]
                    except Exception: pass
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()

        if not sub:
            flash("LinkedIn kullanıcı bilgisi alınamadı. Lütfen tekrar deneyin.", "danger")
            return redirect(url_for("home"))

        with engine.begin() as con:
            row = con.execute(text("SELECT id FROM users WHERE linkedin_id=:lid"), {"lid": sub}).first()
            if row:
                uid = row[0]; con.execute(text("UPDATE users SET name=:n WHERE id=:id"), {"n": name, "id": uid})
            else:
                if is_postgres(engine):
                    uid = con.execute(text("""
                        INSERT INTO users (linkedin_id, name, avatar_url, edu_email)
                        VALUES (:lid, :n, NULL, :e) RETURNING id
                    """), {"lid": sub, "n": name, "e": email}).first()[0]
                else:
                    con.execute(text("""
                        INSERT INTO users (linkedin_id, name, avatar_url, edu_email)
                        VALUES (:lid, :n, NULL, :e)
                    """), {"lid": sub, "n": name, "e": email})
                    uid = con.execute(text("SELECT last_insert_rowid()")).scalar()

        avatar_url_final = None
        if avatar_remote:
            local_path = os.path.join(AVATAR_DIR, f"{uid}.jpg")
            if _download_image_to_local(avatar_remote, local_path):
                web_rel = local_path.split(os.path.join(BASE_DIR, "static"))[-1].replace("\\","/")
                avatar_url_final = "/static" + web_rel
        if not avatar_url_final and avatar_remote: avatar_url_final = avatar_remote

        with engine.begin() as con:
            con.execute(text("UPDATE users SET avatar_url=:a, avatar_cached_at=:t WHERE id=:id"),
                        {"a": avatar_url_final, "t": now_ts(), "id": uid})

        session["uid"] = uid
        flash("Giriş başarılı.", "success")

        nxt = session.get("next_url")
        if email and allowed_edu(email):
            return redirect(url_for("verify", next=nxt) if nxt else url_for("verify"))
        return redirect(nxt or url_for("home"))

    # ---- Home / Profile / Panels ----
    @app.get("/")
    def home():
        user = current_user()
        my_clubs = []; my_events = []; all_events = []
        try:
            with engine.begin() as con:
                if user:
                    my_clubs = con.execute(text("""
                      SELECT c.* FROM clubs c
                      JOIN club_members m ON m.club_id=c.id
                      WHERE m.user_id=:u
                      ORDER BY c.created_at DESC
                    """), {"u": user["id"]}).mappings().all()
                    my_events = con.execute(text("""
                      SELECT e.*, c.name AS club_name, c.banner_url AS club_banner
                      FROM events e JOIN clubs c ON c.id=e.club_id
                      WHERE e.club_id IN (SELECT club_id FROM club_members WHERE user_id=:u)
                      ORDER BY COALESCE(e.starts_at, e.created_at) DESC
                      LIMIT 24
                    """), {"u": user["id"]}).mappings().all()
                all_events = con.execute(text("""
                  SELECT e.*, c.name AS club_name, e.banner_url AS event_banner, c.banner_url AS club_banner
                  FROM events e JOIN clubs c ON c.id=e.club_id
                  ORDER BY COALESCE(e.starts_at, e.created_at) DESC
                  LIMIT 48
                """)).mappings().all()
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()
            flash("DB erişimi başarısız.", "warning")

        fallback = "<h2>Home</h2><p style='opacity:.8'>Şablon yoksa bu ekran görünür.</p>"
        return try_render("home.html", user=user, my_clubs=my_clubs, my_events=my_events, all_events=all_events,
                          page_title="Anasayfa", fallback_html=fallback)

    @app.get("/profile")
    def profile():
        user = current_user()
        if not user: return redirect(url_for("home"))
        memberships = []
        try:
            with engine.begin() as con:
                memberships = con.execute(text("""
                  SELECT c.name, c.id, m.role 
                  FROM club_members m JOIN clubs c ON c.id=m.club_id
                  WHERE m.user_id=:u ORDER BY c.name
                """), {"u": user["id"]}).mappings().all()
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()
        return try_render("profile.html", user=user, memberships=memberships,
                          page_title="Profil", fallback_html="")

    @app.get("/panellerim")
    def my_panels():
        user = current_user()
        if not user: return redirect(url_for("home"))
        admin_clubs = []
        try:
            with engine.begin() as con:
                admin_clubs = con.execute(text("""
                  SELECT c.* FROM club_members m 
                  JOIN clubs c ON c.id=m.club_id
                  WHERE m.user_id=:u AND (LOWER(m.role) != 'member')
                  ORDER BY c.created_at DESC
                """), {"u": user["id"]}).mappings().all()
        except Exception:
            if DEBUG_TRACE: traceback.print_exc()
        return try_render("panels.html", user=user, admin_clubs=admin_clubs,
                          page_title="Panellerim", fallback_html="")

    # ---- Club: NEW (eksikti) ----
    @app.get("/clubs/new")
    def club_new():
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        return try_render("club_new.html", user=user, page_title="Yeni Kulüp", fallback_html="""
          <h2>Yeni Kulüp</h2>
          <form method='post' action='/clubs/new'><input name='name' required><button>Oluştur</button></form>
        """)

    @app.post("/clubs/new")
    def club_new_post():
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Kulüp adı gerekli.", "danger")
            return redirect(url_for("club_new"))
        with engine.begin() as con:
            # clubs
            if is_postgres(engine):
                club_id = con.execute(text("""
                  INSERT INTO clubs (name, owner_user_id, created_at) VALUES (:n,:u,:t) RETURNING id
                """), {"n": name, "u": user["id"], "t": now_ts()}).first()[0]
            else:
                con.execute(text("""
                  INSERT INTO clubs (name, owner_user_id, created_at) VALUES (:n,:u,:t)
                """), {"n": name, "u": user["id"], "t": now_ts()})
                club_id = con.execute(text("SELECT last_insert_rowid()")).scalar()
            # owner membership
            con.execute(text("""
              INSERT INTO club_members (club_id,user_id,role,joined_at) VALUES (:c,:u,'owner',:t)
            """), {"c": club_id, "u": user["id"], "t": now_ts()})
        flash("Kulüp oluşturuldu.", "success")
        return redirect(url_for("club_dashboard", club_id=club_id))

    # ---- Club: DASHBOARD
    @app.get("/clubs/<int:club_id>")
    def club_dashboard(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            members = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, m.role
              FROM club_members m JOIN users u ON u.id=m.user_id
              WHERE m.club_id=:c ORDER BY u.name
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
        is_admin = is_admin_or_owner(club_id, user["id"])
        return try_render("club_dashboard.html", user=user, club=club, members=members,
                          meetings=meetings, events=events, is_admin=is_admin,
                          page_title=f"{club['name']}", fallback_html="")

    # ---- Club: ANALYTICS (eksikti)
    @app.get("/clubs/<int:club_id>/analysis")
    def club_analytics(club_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        # yalnız admin-like görebilsin
        if not is_admin_or_owner(club_id, user["id"]):
            flash("Kulüp analizine sadece admin-like profiller erişebilir.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club: abort(404)
            total_events = con.execute(text("SELECT COUNT(*) FROM events WHERE club_id=:c"), {"c": club_id}).scalar() or 0
            total_checkins = con.execute(text("""
              SELECT COUNT(*) FROM checkins ci JOIN events e ON e.id=ci.event_id WHERE e.club_id=:c
            """), {"c": club_id}).scalar() or 0
            unique_attendees = con.execute(text("""
              SELECT COUNT(DISTINCT ci.user_id)
              FROM checkins ci JOIN events e ON e.id=ci.event_id WHERE e.club_id=:c
            """), {"c": club_id}).scalar() or 0
            # tekrarlayanlar: birden fazla etkinliğe check-in yapanlar
            repeaters = con.execute(text("""
              SELECT COUNT(*) FROM (
                SELECT ci.user_id, COUNT(DISTINCT ci.event_id) AS k
                FROM checkins ci JOIN events e ON e.id=ci.event_id
                WHERE e.club_id=:c GROUP BY ci.user_id HAVING k>1
              ) t
            """), {"c": club_id}).scalar() or 0
            # etkinlik listesi + checkin sayısı
            events = con.execute(text("""
              SELECT e.id, e.title, COALESCE(e.starts_at, e.created_at) AS tkey, e.category,
                     (SELECT COUNT(*) FROM checkins x WHERE x.event_id=e.id) AS checkin_count
              FROM events e WHERE e.club_id=:c
              ORDER BY tkey DESC
            """), {"c": club_id}).mappings().all()
        return try_render("club_analysis.html",
                          user=user, club=club,
                          total_events=total_events, total_checkins=total_checkins,
                          unique_attendees=unique_attendees, repeaters=repeaters,
                          events=events, page_title=f"{club['name']} Analiz", fallback_html="")

    # ---- Event: NEW/ANALYTICS/QR (mevcut akış + canlı ekran endpoint’i)
    def _parse_dt_local(dt_str):
        if not dt_str: return None
        try:
            import datetime as dtm
            return time.mktime(dtm.datetime.strptime(dt_str, "%Y-%m-%dT%H:%M").timetuple())
        except Exception:
            return None

    @app.get("/clubs/<int:club_id>/events/new")
    def event_new(club_id):
        user = current_user()
        if not user: return redirect(url_for("li_login", next=request.url))
        if not is_admin_or_owner(club_id, user["id"]):
            flash("Bu kulüpte etkinlik oluşturma yetkin yok.", "danger")
            return redirect(url_for("club_dashboard", club_id=club_id))
        fallback = f"""
        <h2>Etkinlik Oluştur</h2>
        <form method="POST" enctype="multipart/form-data" action="{url_for('event_new_post', club_id=club_id)}" style="display:grid;gap:8px;max-width:480px">
          <input name="title" placeholder="Başlık" required />
          <select name="category"><option value="event">Etkinlik</option><option value="meeting">Toplantı</option></select>
          <label>Başlangıç: <input type="datetime-local" name="starts_at"></label>
          <label>Bitiş: <input type="datetime-local" name="ends_at"></label>
          <label>Banner: <input type="file" name="banner" accept="image/*"></label>
          <button>Oluştur</button>
        </form>"""
        return try_render("event_create.html", user=user, club_id=club_id,
                          page_title="Etkinlik Oluştur", fallback_html=fallback)

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
                event_id = con.execute(text("""
                  INSERT INTO events (club_id, title, category, starts_at, ends_at, qr_secret, created_by, created_at)
                  VALUES (:c,:t,:cat,:s,:e,:q,:u,:now) RETURNING id
                """), {"c": club_id, "t": title, "cat": category, "s": starts_at, "e": ends_at,
                       "q": qr_secret, "u": user["id"], "now": now_ts()}).first()[0]
            else:
                con.execute(text("""
                  INSERT INTO events (club_id, title, category, starts_at, ends_at, qr_secret, created_by, created_at)
                  VALUES (:c,:t,:cat,:s,:e,:q,:u,:now)
                """), {"c": club_id, "t": title, "cat": category, "s": starts_at, "e": ends_at,
                       "q": qr_secret, "u": user["id"], "now": now_ts()})
                event_id = con.execute(text("SELECT last_insert_rowid()")).scalar()
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
    def event_analytics(event_id): return _event_analytics_impl(event_id)

    @app.get("/events/<int:event_id>/analysis")
    def event_analytics_alias(event_id): return _event_analytics_impl(event_id)

    def _event_analytics_impl(event_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev: abort(404)
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": ev["club_id"]}).mappings().first()
            if not club: abort(404)
            is_member, is_admin = user_membership(ev["club_id"], user["id"])
            if not is_admin:
                flash("Etkinlik analitiğine sadece admin-like profiller erişebilir.", "warning")
                return redirect(url_for("club_dashboard", club_id=ev["club_id"]))
            attendees = con.execute(text("""
              SELECT u.id, u.name, u.avatar_url, u.edu_email, ci.checked_at
              FROM checkins ci JOIN users u ON u.id=ci.user_id
              WHERE ci.event_id=:e ORDER BY u.name
            """), {"e": event_id}).mappings().all()
            member_count = con.execute(text("SELECT COUNT(*) FROM club_members WHERE club_id=:c"),
                                       {"c": ev["club_id"]}).scalar() or 0
            events_all = con.execute(text("""
              SELECT id, title, COALESCE(starts_at, created_at) AS tkey, created_at
              FROM events WHERE club_id=:c ORDER BY COALESCE(starts_at, created_at) ASC, id ASC
            """), {"c": ev["club_id"]}).mappings().all()
        # devam edenler hesabı
        cur_key = ev["starts_at"] if ev["starts_at"] else ev["created_at"]
        next_id = None
        for e in events_all:
            if e["id"] == ev["id"]: continue
            if e["tkey"] and cur_key and e["tkey"] > cur_key: next_id = e["id"]; break
        if not next_id and len(events_all) >= 2:
            ids = [x["id"] for x in events_all]
            try:
                idx = ids.index(ev["id"]); 
                if idx < len(ids)-1: next_id = ids[idx+1]
            except ValueError: pass
        total_att = len(attendees); continued = 0
        if next_id and total_att > 0:
            ids = [str(a["id"]) for a in attendees]
            placeholders = ",".join(ids) if ids else "0"
            with engine.begin() as con:
                q = text(f"SELECT COUNT(*) FROM checkins WHERE event_id=:ne AND user_id IN ({placeholders})")
                continued = con.execute(q, {"ne": next_id}).scalar() or 0
        att_rate = (total_att / member_count * 100.0) if member_count else 0.0
        cont_rate = (continued / total_att * 100.0) if total_att else 0.0
        return try_render("event_analytics.html",
                          user=user, club=club, event=ev, attendees=attendees,
                          member_count=member_count, total_att=total_att,
                          att_rate=att_rate, continued=continued, cont_rate=cont_rate,
                          page_title="Etkinlik Analitiği", fallback_html="")

    # ---- Event: canlı ekran (eksikti)
    @app.get("/events/<int:event_id>/live")
    def event_live(event_id):
        user = current_user()
        if not user: return redirect(url_for("home"))
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev: abort(404)
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": ev["club_id"]}).mappings().first()
            if not club: abort(404)
        # basit bir canlı/QR ekranı
        join_url = app.config["HOST_URL"] + url_for("join") + f"?e={event_id}&q={quote(ev['qr_secret'])}"
        fallback = f"<h2>{ev['title']}</h2><p>QR ile katıl: <a href='{join_url}'>{join_url}</a></p><img src='{url_for('event_qr_png', event_id=event_id)}' alt='QR'/>"
        return try_render("event_live_qr.html", user=user, club=club, event=ev,
                          join_url=join_url, page_title="Canlı Ekran", fallback_html=fallback)

    # ---- Join / QR / Export
    @app.get("/join")
    def join():
        e = request.args.get("e", type=int)
        q = request.args.get("q", type=str)
        if not e or not q:
            flash("Etkinlik bilgisi eksik.", "danger"); return redirect(url_for("home"))
        user = current_user()
        if not user:
            session["next_url"] = request.url
            return redirect(url_for("li_login"))
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": e}).mappings().first()
            if not ev: flash("Etkinlik bulunamadı.", "danger"); return redirect(url_for("home"))
            if ev["qr_secret"] != q:
                flash("Geçersiz QR.", "danger"); return redirect(url_for("home"))
            row = con.execute(text("SELECT role FROM club_members WHERE club_id=:c AND user_id=:u"),
                              {"c": ev["club_id"], "u": user["id"]}).first()
            if not row:
                con.execute(text("""
                  INSERT INTO club_members (club_id,user_id,role,joined_at)
                  VALUES (:c,:u,'member',:t)
                """), {"c": ev["club_id"], "u": user["id"], "t": now_ts()})
            con.execute(text("""
              INSERT OR IGNORE INTO checkins (event_id,user_id,checked_at,via_qr_secret)
              VALUES (:e,:u,:t,:q)
            """) if not is_postgres(engine) else text("""
              INSERT INTO checkins (event_id,user_id,checked_at,via_qr_secret)
              VALUES (:e,:u,:t,:q) ON CONFLICT (event_id, user_id) DO NOTHING
            """), {"e": e, "u": user["id"], "t": now_ts(), "q": q})
        flash("Yoklamaya eklendin. Hoş geldin!", "success")
        return redirect(url_for("event_analytics", event_id=e))

    @app.get("/events/<int:event_id>/qr.png")
    def event_qr_png(event_id):
        user = current_user()
        if not user: return abort(401)
        with engine.begin() as con:
            ev = con.execute(text("SELECT id, qr_secret, club_id, created_by FROM events WHERE id=:id"),
                             {"id": event_id}).mappings().first()
            if not ev: return abort(404)
        if not (is_admin_or_owner(ev["club_id"], user["id"]) or ev["created_by"] == user["id"]):
            return abort(403)
        join_url = app.config["HOST_URL"] + url_for("join") + f"?e={event_id}&q={quote(ev['qr_secret'])}"
        img = qrcode.make(join_url); buf = io.BytesIO(); img.save(buf, format="PNG"); buf.seek(0)
        return send_file(buf, mimetype="image/png", max_age=0)

    @app.get("/events/<int:event_id>/export.csv")
    def event_export_csv(event_id):
        user = current_user()
        if not user: return abort(401)
        with engine.begin() as con:
            ev = con.execute(text("SELECT id, club_id, created_by, title FROM events WHERE id=:id"),
                             {"id": event_id}).mappings().first()
            if not ev: abort(404)
            if not (is_admin_or_owner(ev["club_id"], user["id"]) or ev["created_by"] == user["id"]):
                return abort(403)
            rows = con.execute(text("""
              SELECT u.id, u.name, u.edu_email, ci.checked_at
              FROM checkins ci JOIN users u ON u.id=ci.user_id
              WHERE ci.event_id=:e ORDER BY u.name
            """), {"e": event_id}).all()
        buf = io.StringIO(); w = csv.writer(buf)
        w.writerow(["user_id","name","edu_email","checked_at"])
        for r in rows: w.writerow([r[0], r[1], r[2] or "", ts2human(r[3])])
        data = buf.getvalue().encode("utf-8-sig")
        return Response(data, headers={"Content-Disposition": f'attachment; filename="event_{event_id}_attendees.csv"'},
                        mimetype="text/csv")

    # ---- EDU verify
    @app.get("/verify")
    def verify():
        user = current_user()
        allowed = os.getenv("EDU_ALLOWED_DOMAINS","")
        return try_render("verify.html", user=user, allowed=allowed, page_title="EDU Doğrulama", fallback_html="")

    # ---- Errors ----
    @app.errorhandler(500)
    def err_500(e):
        if DEBUG_TRACE: traceback.print_exc()
        return render_template_string(
            "<h2 style='font-family:system-ui;color:#eee;background:#111;padding:20px'>Bir şeyler ters gitti (500).</h2>"
            "<p style='padding:0 20px;color:#ddd'>Şablon eksikse sayfa açılmazdı; şimdi fallback devrede. Logları kontrol edin.</p>"
        ), 500

    @app.context_processor
    def inject_globals(): return {"HOST_URL": app.config["HOST_URL"]}

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

