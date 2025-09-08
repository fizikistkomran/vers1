# connect_routes.py
import time
from flask import Blueprint, request, redirect, url_for, flash, abort, session
from sqlalchemy import text

bp = Blueprint("connections", __name__)

def now_ts():
    return float(time.time())

def canonical_pair(a: int, b: int):
    return (a, b) if a <= b else (b, a)

# ---- Bu yardımcılar, ana uygulamadaki fonksiyonlarınıza delegasyon içindir.
# app.py içinde aynı isimlerle fonksiyonlarınız varsa onları kullanın.
def get_engine(app):
    return app.config.get("SQLALCHEMY_ENGINE") or app.extensions["engine"]

def current_user_id():
    return session.get("uid") or session.get("user_id")

def is_member(engine, club_id: int, user_id: int) -> bool:
    with engine.begin() as con:
        row = con.execute(text("""
          SELECT 1 FROM club_members WHERE club_id=:c AND user_id=:u
        """), {"c": club_id, "u": user_id}).first()
        return bool(row)

def is_admin_or_owner(engine, club_id: int, user_id: int) -> bool:
    with engine.begin() as con:
        role = con.execute(text("""
          SELECT COALESCE(LOWER(role),'member') FROM club_members WHERE club_id=:c AND user_id=:u
        """), {"c": club_id, "u": user_id}).scalar()
        owner = con.execute(text("SELECT owner_user_id FROM clubs WHERE id=:c"), {"c": club_id}).scalar()
        return bool((role and role != "member") or (owner == user_id))

def ensure_graph_table(engine):
    with engine.begin() as con:
        # Postgres/SQLite uyumlu light DDL
        con.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS graph_edges(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          club_id INTEGER NOT NULL,
          src_user_id INTEGER NOT NULL,
          dst_user_id INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',   -- pending|accepted|declined
          requested_by INTEGER,
          created_at REAL,
          responded_at REAL,
          UNIQUE (club_id, src_user_id, dst_user_id)
        )
        """)
        # Postgres'ta AUTOINCREMENT yerine SERIAL kullanılıyor olabilir; varsa yoksa zaten tablo mevcuttur.

@bp.before_app_first_request
def _prepare():
    engine = get_engine(bp.app)
    ensure_graph_table(engine)

@bp.post("/clubs/<int:club_id>/connect/request")
def connect_request(club_id):
    uid = current_user_id()
    if not uid: return abort(401)
    target = request.form.get("target_user_id", type=int)
    if not target or target == uid:
        flash("Hedef kullanıcı geçersiz.", "warning")
        return redirect(url_for("club_dashboard", club_id=club_id))

    engine = get_engine(bp.app)
    if not is_member(engine, club_id, uid) or not is_member(engine, club_id, target):
        flash("Her iki tarafın da kulüp üyesi olması gerekir.", "danger")
        return redirect(url_for("club_dashboard", club_id=club_id))

    s, d = canonical_pair(uid, target)
    with engine.begin() as con:
        row = con.execute(text("""
          SELECT status FROM graph_edges WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
        """), {"c": club_id, "s": s, "d": d}).mappings().first()

        if row is None:
            con.execute(text("""
              INSERT INTO graph_edges (club_id, src_user_id, dst_user_id, status, requested_by, created_at)
              VALUES (:c,:s,:d,'pending',:rq,:t)
            """), {"c": club_id, "s": s, "d": d, "rq": uid, "t": now_ts()})
            flash("Bağlantı isteği gönderildi.", "success")
        else:
            st = (row["status"] or "").lower()
            if st == "accepted":
                flash("Zaten bağlısınız.", "info")
            elif st == "pending":
                flash("Zaten bekleyen bir istek var.", "info")
            else:
                con.execute(text("""
                  UPDATE graph_edges SET status='pending', requested_by=:rq, responded_at=NULL
                  WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
                """), {"rq": uid, "c": club_id, "s": s, "d": d})
                flash("Bağlantı isteği tekrar gönderildi.", "success")
    return redirect(url_for("club_dashboard", club_id=club_id))

@bp.post("/clubs/<int:club_id>/connect/cancel")
def connect_cancel(club_id):
    uid = current_user_id()
    if not uid: return abort(401)
    target = request.form.get("target_user_id", type=int)
    if not target: return abort(400)

    s, d = canonical_pair(uid, target)
    engine = get_engine(bp.app)
    with engine.begin() as con:
        row = con.execute(text("""
          SELECT status, requested_by FROM graph_edges 
          WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
        """), {"c": club_id, "s": s, "d": d}).mappings().first()
        if not row or row["status"] != "pending" or row["requested_by"] != uid:
            flash("İptal edilecek bekleyen isteğin yok.", "warning")
        else:
            con.execute(text("""
              DELETE FROM graph_edges 
              WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d AND status='pending' AND requested_by=:rq
            """), {"c": club_id, "s": s, "d": d, "rq": uid})
            flash("İstek iptal edildi.", "success")
    return redirect(url_for("club_dashboard", club_id=club_id))

@bp.post("/clubs/<int:club_id>/connect/respond")
def connect_respond(club_id):
    uid = current_user_id()
    if not uid: return abort(401)
    s = request.form.get("src_user_id", type=int)
    d = request.form.get("dst_user_id", type=int)
    action = (request.form.get("action") or "").strip().lower()
    if not (s and d and action in {"accept","decline"}): return abort(400)
    if uid not in (s, d):
        return abort(403)

    engine = get_engine(bp.app)
    with engine.begin() as con:
        row = con.execute(text("""
          SELECT status, requested_by FROM graph_edges 
          WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
        """), {"c": club_id, "s": s, "d": d}).mappings().first()
        if not row or (row["status"] or "").lower() != "pending":
            flash("Bekleyen bir istek bulunamadı.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))
        if row["requested_by"] == uid:
            flash("Kendi gönderdiğin isteği kabul/ret edemezsin.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))

        new_status = "accepted" if action == "accept" else "declined"
        con.execute(text("""
          UPDATE graph_edges 
          SET status=:st, responded_at=:t
          WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
        """), {"st": new_status, "t": now_ts(), "c": club_id, "s": s, "d": d})
        flash("Seçimin kaydedildi.", "success")
    return redirect(url_for("club_dashboard", club_id=club_id))

