# connect_routes.py
import os, re, time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Blueprint, request, redirect, url_for, flash, abort, session

bp = Blueprint("connections", __name__)

# ---------- DSN / DB helpers ----------
def _clean_dsn(url: str) -> str:
    """
    SQLAlchemy tarzı DSN'leri psycopg2 için temizler.
    - postgresql+psycopg2://  -> postgresql://
    - postgres://             -> postgresql://
    - sslmode parametresini garanti eder (değer yoksa =require ekler)
    """
    u = (url or "").strip()
    if not u:
        return u

    # Şema düzeltme
    if u.startswith("postgresql+psycopg2://"):
        u = "postgresql://" + u.split("postgresql+psycopg2://", 1)[1]
    elif u.startswith("postgres://"):
        u = "postgresql://" + u[len("postgres://"):]

    # Query düzenleme (sslmode kontrolü)
    parts = urlsplit(u)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))

    if "sslmode" not in q or not q.get("sslmode"):
        q["sslmode"] = "require"

    new_query = urlencode(q, doseq=True)
    cleaned = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    return cleaned

def _get_db_params():
    """
    Railway genelde DATABASE_URL sağlar. Onu kullan, yoksa tek tek env değişkenlerine düş.
    """
    raw = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or ""
    if raw:
        return {"dsn": _clean_dsn(raw)}
    # Yedek env değişkenleri
    return {
        "dbname": os.getenv("PGDATABASE", os.getenv("DATABASE_NAME", "railway")),
        "user": os.getenv("PGUSER", os.getenv("DATABASE_USER", "postgres")),
        "password": os.getenv("PGPASSWORD", os.getenv("DATABASE_PASSWORD", "")),
        "host": os.getenv("PGHOST", os.getenv("DATABASE_HOST", "localhost")),
        "port": int(os.getenv("PGPORT", os.getenv("DATABASE_PORT", "5432"))),
        "sslmode": os.getenv("PGSSLMODE", "require"),
    }

def get_db_connection():
    params = _get_db_params()
    if "dsn" in params:
        # DSN string ile bağlan
        return psycopg2.connect(params["dsn"], cursor_factory=RealDictCursor)
    # Parametre bazlı bağlan
    return psycopg2.connect(
        dbname=params["dbname"],
        user=params["user"],
        password=params["password"],
        host=params["host"],
        port=params["port"],
        sslmode=params.get("sslmode", "require"),
        cursor_factory=RealDictCursor,
    )

def now_ts() -> float:
    return float(time.time())

def canonical_pair(a: int, b: int):
    return (a, b) if a <= b else (b, a)

# ---------- Schema bootstrap ----------
def ensure_graph_table():
    """
    PostgreSQL uyumlu tablo. Varsa dokunmaz; yoksa oluşturur.
    """
    ddl = """
    CREATE TABLE IF NOT EXISTS graph_edges(
      id SERIAL PRIMARY KEY,
      club_id INTEGER NOT NULL,
      src_user_id INTEGER NOT NULL,
      dst_user_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',   -- pending|accepted|declined
      requested_by INTEGER,
      created_at DOUBLE PRECISION,
      responded_at DOUBLE PRECISION,
      UNIQUE (club_id, src_user_id, dst_user_id)
    );
    """
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute(ddl)
        conn.commit()

def is_member(club_id: int, user_id: int) -> bool:
    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("""
                SELECT 1 FROM club_members WHERE club_id = %s AND user_id = %s
            """, (club_id, user_id))
            return c.fetchone() is not None

# İstersen admin-like gerektir; şimdilik kulüp üyesi olmak yeterli
def can_interact(club_id: int, user_id: int) -> bool:
    return is_member(club_id, user_id)

# ---------- Hooks ----------
@bp.before_app_request
def _boot_if_needed():
    # CREATE TABLE IF NOT EXISTS çok hafif bir çağrı; her request'te güvenli.
    ensure_graph_table()

# ---------- Routes ----------
@bp.post("/clubs/<int:club_id>/connect/request")
def connect_request(club_id):
    uid = session.get("uid") or session.get("user_id")
    if not uid:
        return abort(401)

    target = request.form.get("target_user_id", type=int)
    if not target or target == uid:
        flash("Hedef kullanıcı geçersiz.", "warning")
        return redirect(url_for("club_dashboard", club_id=club_id))

    if not (can_interact(club_id, uid) and can_interact(club_id, target)):
        flash("Her iki tarafın da kulüp üyesi olması gerekir.", "danger")
        return redirect(url_for("club_dashboard", club_id=club_id))

    s, d = canonical_pair(uid, target)

    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("""
                SELECT status FROM graph_edges 
                WHERE club_id=%s AND src_user_id=%s AND dst_user_id=%s
            """, (club_id, s, d))
            row = c.fetchone()

            if row is None:
                c.execute("""
                    INSERT INTO graph_edges (club_id, src_user_id, dst_user_id, status, requested_by, created_at)
                    VALUES (%s, %s, %s, 'pending', %s, %s)
                """, (club_id, s, d, uid, now_ts()))
                conn.commit()
                flash("Bağlantı isteği gönderildi.", "success")
            else:
                st = (row["status"] or "").lower()
                if st == "accepted":
                    flash("Zaten bağlısınız.", "info")
                elif st == "pending":
                    flash("Zaten bekleyen bir istek var.", "info")
                else:
                    c.execute("""
                        UPDATE graph_edges 
                        SET status='pending', requested_by=%s, responded_at=NULL
                        WHERE club_id=%s AND src_user_id=%s AND dst_user_id=%s
                    """, (uid, club_id, s, d))
                    conn.commit()
                    flash("Bağlantı isteği tekrar gönderildi.", "success")

    return redirect(url_for("club_dashboard", club_id=club_id))

@bp.post("/clubs/<int:club_id>/connect/cancel")
def connect_cancel(club_id):
    uid = session.get("uid") or session.get("user_id")
    if not uid:
        return abort(401)

    target = request.form.get("target_user_id", type=int)
    if not target:
        return abort(400)

    s, d = canonical_pair(uid, target)

    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("""
                SELECT status, requested_by FROM graph_edges
                WHERE club_id=%s AND src_user_id=%s AND dst_user_id=%s
            """, (club_id, s, d))
            row = c.fetchone()

            if (not row) or (row["status"] != "pending") or (row["requested_by"] != uid):
                flash("İptal edilecek bekleyen bir isteğin yok.", "warning")
            else:
                c.execute("""
                    DELETE FROM graph_edges
                    WHERE club_id=%s AND src_user_id=%s AND dst_user_id=%s
                      AND status='pending' AND requested_by=%s
                """, (club_id, s, d, uid))
                conn.commit()
                flash("İstek iptal edildi.", "success")

    return redirect(url_for("club_dashboard", club_id=club_id))

@bp.post("/clubs/<int:club_id>/connect/respond")
def connect_respond(club_id):
    uid = session.get("uid") or session.get("user_id")
    if not uid:
        return abort(401)

    s = request.form.get("src_user_id", type=int)
    d = request.form.get("dst_user_id", type=int)
    action = (request.form.get("action") or "").strip().lower()
    if not (s and d and action in {"accept", "decline"}):
        return abort(400)

    if uid not in (s, d):
        return abort(403)

    with get_db_connection() as conn:
        with conn.cursor() as c:
            c.execute("""
                SELECT status, requested_by FROM graph_edges
                WHERE club_id=%s AND src_user_id=%s AND dst_user_id=%s
            """, (club_id, s, d))
            row = c.fetchone()

            if (not row) or (row["status"] or "").lower() != "pending":
                flash("Bekleyen bir istek bulunamadı.", "warning")
                return redirect(url_for("club_dashboard", club_id=club_id))

            if row["requested_by"] == uid:
                flash("Kendi gönderdiğin isteği kabul/ret edemezsin.", "warning")
                return redirect(url_for("club_dashboard", club_id=club_id))

            new_status = "accepted" if action == "accept" else "declined"
            c.execute("""
                UPDATE graph_edges
                SET status=%s, responded_at=%s
                WHERE club_id=%s AND src_user_id=%s AND dst_user_id=%s
            """, (new_status, now_ts(), club_id, s, d))
            conn.commit()
            flash("Seçimin kaydedildi.", "success")

    return redirect(url_for("club_dashboard", club_id=club_id))

