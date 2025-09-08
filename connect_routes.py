# connect_routes.py
import os, time
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Blueprint, request, redirect, url_for, flash, abort, session

bp = Blueprint("connections", __name__)

# ---------- DB helpers (psycopg2) ----------
def _get_db_params():
    """
    Railway genelde DATABASE_URL verir.
    Yoksa manuel env değişkenleri veya app.py’de kullandığın değerlerle doldur.
    """
    url = os.getenv("DATABASE_URL")
    if url:
        # psycopg2 DSN formatını kabul eder
        return {"dsn": url}
    # Yedek: manuel param (app.py’de olanları buraya da yansıt)
    return {
        "dbname": os.getenv("PGDATABASE", "railway"),
        "user": os.getenv("PGUSER", "postgres"),
        "password": os.getenv("PGPASSWORD", "postgres"),
        "host": os.getenv("PGHOST", "localhost"),
        "port": int(os.getenv("PGPORT", "5432")),
    }

def get_db_connection():
    params = _get_db_params()
    if "dsn" in params:
        return psycopg2.connect(params["dsn"], cursor_factory=RealDictCursor)
    return psycopg2.connect(
        dbname=params["dbname"],
        user=params["user"],
        password=params["password"],
        host=params["host"],
        port=params["port"],
        cursor_factory=RealDictCursor,
    )

def now_ts() -> float:
    return float(time.time())

def canonical_pair(a: int, b: int):
    return (a, b) if a <= b else (b, a)

# ---------- Schema bootstrap ----------
def ensure_graph_table():
    """
    PostgreSQL ile uyumlu DDL.
    Railway ilk istekte tabloyu oluşturur; varsa zarar vermez.
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
            row = c.fetchone()
            return bool(row)

# İstersen admin-like kısıt koyarsın; şimdilik sadece üyelik yeter
def can_interact(club_id: int, user_id: int) -> bool:
    return is_member(club_id, user_id)

# ---------- Routes ----------
@bp.before_app_request
def _boot_if_needed():
    # Her request’te hızlı kontrol; tablo yoksa oluştur.
    # (CREATE IF NOT EXISTS cheap’tir; sorun olmaz)
    ensure_graph_table()

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

