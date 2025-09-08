# connect_routes.py
# Bu sürüm, app.py'deki global veritabanı bağlantısını kullanır.

import os, re, time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from flask import Blueprint, request, redirect, url_for, flash, abort, session
from sqlalchemy import text
from app import engine, current_user, canonical_pair, now_ts, is_member, can_interact

bp = Blueprint("connections", __name__)

# NOT: Artık get_db_connection() veya ensure_graph_table() gibi fonksiyonlar burada yok.
# Onlar app.py'de tanımlandı ve global olarak kullanılıyor.

# ---------- Routes ----------
@bp.post("/clubs/<int:club_id>/connect/request")
def connect_request(club_id):
    user = current_user()
    if not user:
        return abort(401)

    target = request.form.get("target_user_id", type=int)
    if not target or target == user["id"]:
        flash("Hedef kullanıcı geçersiz.", "warning")
        return redirect(url_for("club_dashboard", club_id=club_id))

    if not (can_interact(club_id, user["id"]) and can_interact(club_id, target)):
        flash("Her iki tarafın da kulüp üyesi olması gerekir.", "danger")
        return redirect(url_for("club_dashboard", club_id=club_id))

    s, d = canonical_pair(user["id"], target)

    with engine.begin() as con:
        row = con.execute(text("""
            SELECT status FROM graph_edges 
            WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
        """), {"c": club_id, "s": s, "d": d}).mappings().first()

        if row is None:
            con.execute(text("""
                INSERT INTO graph_edges (club_id, src_user_id, dst_user_id, status, requested_by, created_at)
                VALUES (:c, :s, :d, 'pending', :req, :ts)
            """), {"c": club_id, "s": s, "d": d, "req": user["id"], "ts": now_ts()})
            flash("Bağlantı isteği gönderildi.", "success")
        else:
            st = (row["status"] or "").lower()
            if st == "accepted":
                flash("Zaten bağlısınız.", "info")
            elif st == "pending":
                flash("Zaten bekleyen bir istek var.", "info")
            else:
                con.execute(text("""
                    UPDATE graph_edges 
                    SET status='pending', requested_by=:req, responded_at=NULL
                    WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
                """), {"req": user["id"], "c": club_id, "s": s, "d": d})
                flash("Bağlantı isteği tekrar gönderildi.", "success")

    return redirect(url_for("club_dashboard", club_id=club_id))

@bp.post("/clubs/<int:club_id>/connect/cancel")
def connect_cancel(club_id):
    user = current_user()
    if not user:
        return abort(401)

    target = request.form.get("target_user_id", type=int)
    if not target:
        return abort(400)

    s, d = canonical_pair(user["id"], target)

    with engine.begin() as con:
        row = con.execute(text("""
            SELECT status, requested_by FROM graph_edges
            WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
        """), {"c": club_id, "s": s, "d": d}).mappings().first()

        if (not row) or (row["status"] != "pending") or (row["requested_by"] != user["id"]):
            flash("İptal edilecek bekleyen bir isteğin yok.", "warning")
        else:
            con.execute(text("""
                DELETE FROM graph_edges
                WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
                  AND status='pending' AND requested_by=:req
            """), {"c": club_id, "s": s, "d": d, "req": user["id"]})
            flash("İstek iptal edildi.", "success")

    return redirect(url_for("club_dashboard", club_id=club_id))

@bp.post("/clubs/<int:club_id>/connect/respond")
def connect_respond(club_id):
    user = current_user()
    if not user:
        return abort(401)

    s = request.form.get("src_user_id", type=int)
    d = request.form.get("dst_user_id", type=int)
    action = (request.form.get("action") or "").strip().lower()
    if not (s and d and action in {"accept", "decline"}):
        return abort(400)

    if user["id"] not in (s, d):
        return abort(403)

    with engine.begin() as con:
        row = con.execute(text("""
            SELECT status, requested_by FROM graph_edges
            WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
        """), {"c": club_id, "s": s, "d": d}).mappings().first()

        if (not row) or (row["status"] or "").lower() != "pending":
            flash("Bekleyen bir istek bulunamadı.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))

        if row["requested_by"] == user["id"]:
            flash("Kendi gönderdiğin isteği kabul/ret edemezsin.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))

        new_status = "accepted" if action == "accept" else "declined"
        con.execute(text("""
            UPDATE graph_edges
            SET status=:new_status, responded_at=:ts
            WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
        """), {"new_status": new_status, "ts": now_ts(), "c": club_id, "s": s, "d": d})
        flash("Seçimin kaydedildi.", "success")

    return redirect(url_for("club_dashboard", club_id=club_id))
