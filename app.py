# app.py — kulüp üyeleri ağı (graf) + bağlantı istekleri + analitik (admin-only)
import os, time, traceback
from flask import (
    Flask, render_template, render_template_string, redirect, url_for,
    request, session, flash, abort, jsonify
)
from sqlalchemy import create_engine, text
from jinja2 import TemplateNotFound

# ------------- Genel yardımcılar -------------
def now_ts() -> float:
    return float(time.time())

def canonical_pair(a: int, b: int):
    return (a, b) if a <= b else (b, a)

# ------------- Uygulama Fabrikası -------------
def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False

    # ---- DB (Railway uyumlu) ----
    DB_URL = os.getenv("DATABASE_URL", "sqlite:///enfekte.db").strip()
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    if DB_URL.startswith("postgresql://"):
        DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
    if DB_URL.startswith("postgresql+psycopg2://") and "sslmode=" not in DB_URL:
        DB_URL += ("&" if "?" in DB_URL else "?") + "sslmode=require"

    pool_size = int(os.getenv("DB_POOL_SIZE", "5"))
    max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "5"))
    pool_recycle = int(os.getenv("DB_POOL_RECYCLE", "280"))

    engine = create_engine(
        DB_URL,
        echo=False,
        future=True,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_recycle=pool_recycle,
        connect_args={"connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "10"))}
        if DB_URL.startswith("postgresql") else {},
    )

    # soğuk uyanış: birkaç kez dene
    attempts = int(os.getenv("DB_CONNECT_ATTEMPTS", "5"))
    delay = 1.0
    for i in range(attempts):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            break
        except Exception as e:
            if i == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 1.6, 5)

    # ---- Şema ----
    def is_postgres() -> bool:
        return engine.dialect.name in ("postgresql", "postgres")

    def current_ts_sql() -> str:
        return "EXTRACT(EPOCH FROM NOW())" if is_postgres() else "strftime('%s','now')"

    def create_schema():
        ts = current_ts_sql()
        ddl = []
        if is_postgres():
            ddl += [
                f"""CREATE TABLE IF NOT EXISTS users(
                    id SERIAL PRIMARY KEY,
                    name TEXT,
                    avatar_url TEXT
                );""",
                f"""CREATE TABLE IF NOT EXISTS clubs(
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    slug TEXT UNIQUE,
                    owner_user_id INTEGER NOT NULL,
                    banner_url TEXT,
                    created_at DOUBLE PRECISION DEFAULT ({ts})
                );""",
                f"""CREATE TABLE IF NOT EXISTS club_members(
                    club_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    joined_at DOUBLE PRECISION DEFAULT ({ts}),
                    PRIMARY KEY (club_id, user_id)
                );""",
                f"""CREATE TABLE IF NOT EXISTS events(
                    id SERIAL PRIMARY KEY,
                    club_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT DEFAULT 'event',
                    starts_at DOUBLE PRECISION,
                    created_at DOUBLE PRECISION DEFAULT ({ts})
                );""",
                f"""CREATE TABLE IF NOT EXISTS checkins(
                    event_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    checked_at DOUBLE PRECISION DEFAULT ({ts}),
                    PRIMARY KEY (event_id, user_id)
                );""",
                f"""CREATE TABLE IF NOT EXISTS graph_edges(
                    id SERIAL PRIMARY KEY,
                    club_id INTEGER NOT NULL,
                    src_user_id INTEGER NOT NULL,
                    dst_user_id INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',   -- pending|accepted|declined
                    requested_by INTEGER,
                    responded_at DOUBLE PRECISION,
                    created_at DOUBLE PRECISION DEFAULT ({ts}),
                    UNIQUE (club_id, src_user_id, dst_user_id)
                );"""
            ]
        else:
            ddl += [
                f"""CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    avatar_url TEXT
                );""",
                f"""CREATE TABLE IF NOT EXISTS clubs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    slug TEXT UNIQUE,
                    owner_user_id INTEGER NOT NULL,
                    banner_url TEXT,
                    created_at REAL DEFAULT ({ts})
                );""",
                f"""CREATE TABLE IF NOT EXISTS club_members(
                    club_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    joined_at REAL DEFAULT ({ts}),
                    PRIMARY KEY (club_id, user_id)
                );""",
                f"""CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    club_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT DEFAULT 'event',
                    starts_at REAL,
                    created_at REAL DEFAULT ({ts})
                );""",
                f"""CREATE TABLE IF NOT EXISTS checkins(
                    event_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    checked_at REAL DEFAULT ({ts}),
                    PRIMARY KEY (event_id, user_id)
                );""",
                f"""CREATE TABLE IF NOT EXISTS graph_edges(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    club_id INTEGER NOT NULL,
                    src_user_id INTEGER NOT NULL,
                    dst_user_id INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    requested_by INTEGER,
                    responded_at REAL,
                    created_at REAL DEFAULT ({ts}),
                    UNIQUE (club_id, src_user_id, dst_user_id)
                );"""
            ]
        with engine.begin() as con:
            for sql in ddl:
                con.exec_driver_sql(sql)

    create_schema()

    # ---- Yardımcılar ----
    ADMIN_LIKE_ROLES = {
        r.strip().lower()
        for r in (os.getenv("ADMIN_LIKE_ROLES", "owner,admin,officer,coordinator,manager,lead,moderator,editor").split(","))
        if r.strip()
    } or {"owner", "admin"}

    @app.template_filter("ts")
    def _ts(ts):  # basit humanize
        try:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))
        except Exception:
            return "-"

    def try_render(tpl, **ctx):
        try:
            return render_template(tpl, **ctx)
        except TemplateNotFound:
            title = ctx.get("page_title") or "Sayfa"
            body = ctx.get("fallback_html") or "<p>Şablon eksik.</p>"
            return render_template_string(
                f"<!doctype html><title>{title}</title><div style='padding:20px;color:#eee;background:#111;font-family:system-ui'>{body}</div>"
            )

    def current_user():
        """Demo amaçlı: gerçek projende oturumu nasıl tutuyorsan oraya bağla."""
        uid = session.get("uid") or session.get("user_id")
        if not uid:
            return None
        with engine.begin() as con:
            row = con.execute(text("SELECT id, name, avatar_url FROM users WHERE id=:u"), {"u": uid}).mappings().first()
            return dict(row) if row else None

    def user_membership(club_id: int, user_id: int):
        with engine.begin() as con:
            row = con.execute(text("SELECT COALESCE(LOWER(role),'member') FROM club_members WHERE club_id=:c AND user_id=:u"),
                              {"c": club_id, "u": user_id}).first()
        is_member = row is not None
        role = (row[0] if row else "member").lower()
        is_admin = is_member and (role in ADMIN_LIKE_ROLES or role != "member")
        return is_member, is_admin

    def is_admin_or_owner(club_id: int, user_id: int) -> bool:
        with engine.begin() as con:
            role = con.execute(text("SELECT COALESCE(LOWER(role),'member') FROM club_members WHERE club_id=:c AND user_id=:u"),
                               {"c": club_id, "u": user_id}).scalar()
            owner = con.execute(text("SELECT owner_user_id FROM clubs WHERE id=:c"), {"c": club_id}).scalar()
        return bool((role and role != "member") or (owner == user_id))

    def get_edge_status(club_id: int, a: int, b: int):
        s, d = canonical_pair(a, b)
        with engine.begin() as con:
            row = con.execute(text("""
                SELECT status, requested_by FROM graph_edges
                WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
            """), {"c": club_id, "s": s, "d": d}).mappings().first()
        return (row["status"], row["requested_by"]) if row else (None, None)

    # ------------- ROUTES -------------

    @app.get("/")
    def home():
        user = current_user()
        return try_render("home.html", user=user, page_title="enfekte.co",
                          fallback_html="<h2>Hoş geldin</h2><p>Soldaki menüden kulübüne git.</p>")

    # ---- KULÜP PANELİ ----
    @app.get("/clubs/<int:club_id>")
    def club_dashboard(club_id):
        user = current_user()
        if not user:
            return redirect(url_for("home"))

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            if not club:
                abort(404)
            members = con.execute(text("""
                SELECT u.id, u.name, u.avatar_url, COALESCE(LOWER(m.role),'member') AS role
                FROM club_members m JOIN users u ON u.id=m.user_id
                WHERE m.club_id=:c
                ORDER BY u.name
            """), {"c": club_id}).mappings().all()
            meetings = con.execute(text("""
                SELECT e.*, COALESCE(starts_at, created_at) AS tkey
                FROM events e WHERE e.club_id=:c AND COALESCE(e.category,'event')='meeting'
                ORDER BY tkey DESC
            """), {"c": club_id}).mappings().all()
            events = con.execute(text("""
                SELECT e.*, COALESCE(starts_at, created_at) AS tkey
                FROM events e WHERE e.club_id=:c AND COALESCE(e.category,'event')='event'
                ORDER BY tkey DESC
            """), {"c": club_id}).mappings().all()

        is_member, is_admin = user_membership(club_id, user["id"])
        owner = is_admin_or_owner(club_id, user["id"])

        # fallback HTML (şablon yoksa)
        connect_rows = []
        for m in members:
            if m["id"] == user["id"]:
                btn = "<em>Ben</em>"
            else:
                st, rq = get_edge_status(club_id, user["id"], m["id"])
                if st is None:
                    btn = f"""
                    <form method="post" action="{url_for('connect_request', club_id=club_id)}" style="display:inline">
                      <input type="hidden" name="target_user_id" value="{m['id']}">
                      <button class="btn-badge">Bağlan</button>
                    </form>"""
                elif st == "pending":
                    if rq == user["id"]:
                        btn = f"""
                        <form method="post" action="{url_for('connect_cancel', club_id=club_id)}" style="display:inline">
                          <input type="hidden" name="target_user_id" value="{m['id']}">
                          <button class="btn-badge" style="opacity:.8">İptal</button>
                        </form>"""
                    else:
                        s, d = canonical_pair(user["id"], m["id"])
                        btn = f"""
                        <form method="post" action="{url_for('connect_respond', club_id=club_id)}" style="display:inline;margin-right:6px">
                          <input type="hidden" name="src_user_id" value="{s}">
                          <input type="hidden" name="dst_user_id" value="{d}">
                          <input type="hidden" name="action" value="accept">
                          <button class="btn-badge">Kabul</button>
                        </form>
                        <form method="post" action="{url_for('connect_respond', club_id=club_id)}" style="display:inline">
                          <input type="hidden" name="src_user_id" value="{s}">
                          <input type="hidden" name="dst_user_id" value="{d}">
                          <input type="hidden" name="action" value="decline">
                          <button class="btn-badge" style="opacity:.8">Reddet</button>
                        </form>"""
                elif st == "accepted":
                    btn = "<span class='chip'>Bağlı</span>"
                else:
                    btn = "<span class='chip' style='opacity:.7'>Reddedildi</span>"
            connect_rows.append(f"""
              <tr>
                <td style='display:flex;gap:8px;align-items:center'>
                  <img src='{m.get('avatar_url') or '/static/avatar-placeholder.png'}' style='width:28px;height:28px;border-radius:50%;object-fit:cover'>
                  {m['name']}
                </td>
                <td><code>{m['role']}</code></td>
                <td>{btn}</td>
              </tr>
            """)

        fallback = f"""
        <div style="position:relative;border-radius:16px;overflow:hidden;border:1px solid #222">
          <div style="height:160px;background:#222 url('{club.get('banner_url') or ''}') center/cover no-repeat"></div>
          <div style="padding:14px">
            <h2 style="margin:0">{club['name']}</h2>
            <div class="sub">Kulüp #{club['id']}</div>
          </div>
        </div>
        <div style="margin:12px 0;display:flex;gap:16px;flex-wrap:wrap">
          <a class="chip" href="{url_for('club_members', club_id=club_id)}">Üyeler & Roller</a>
          <a class="chip" href="{url_for('club_graph', club_id=club_id)}">Grafik (tam ekran)</a>
          {"<a class='chip' href='"+url_for('club_analytics', club_id=club_id)+"'>Analitik</a>" if is_admin else ""}
        </div>
        {"<iframe src='"+url_for('club_graph', club_id=club_id)+"' style='width:100%;height:560px;border:1px solid #333;border-radius:12px;background:#0e0f13' loading='lazy'></iframe>" if is_member else "<div class='empty list'>Grafiği görmek için üye ol.</div>"}
        <h3 style="margin-top:16px">Üyeler</h3>
        <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse">
          <tr><th>Üye</th><th>Rol</th><th>Bağlantı</th></tr>
          {''.join(connect_rows)}
        </table>
        """
        return try_render("club_dashboard.html",
                          user=user, club=club, members=members,
                          meetings=meetings, events=events,
                          is_member=is_member, owner=is_admin,  # şablon geriye dönük uyum
                          page_title=club["name"], fallback_html=fallback)

    # ---- ÜYELER & ROLLER (owner) ----
    @app.get("/clubs/<int:club_id>/members")
    def club_members(club_id):
        user = current_user()
        if not user:
            return redirect(url_for("home"))
        if not is_admin_or_owner(club_id, user["id"]):
            flash("Sadece owner/admin-like bu sayfayı görebilir.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            members = con.execute(text("""
                SELECT u.id, u.name, u.avatar_url, COALESCE(LOWER(m.role),'member') AS role
                FROM club_members m JOIN users u ON u.id=m.user_id
                WHERE m.club_id=:c ORDER BY u.name
            """), {"c": club_id}).mappings().all()

        roles = sorted({"member"} | ADMIN_LIKE_ROLES - {"owner"})

        # basit fallback tablo
        rows = []
        for m in members:
            rows.append(f"""
            <tr>
              <td>{m['name']}</td>
              <td><code>{m['role']}</code></td>
              <td>
                <form method="post" action="{url_for('club_set_role', club_id=club_id)}" style="display:inline">
                  <input type="hidden" name="user_id" value="{m['id']}">
                  <select name="role">
                    {''.join([f"<option value='{r}' {'selected' if m['role']==r else ''}>{r}</option>" for r in roles])}
                  </select>
                  <button>Kaydet</button>
                </form>
              </td>
            </tr>
            """)
        fallback = f"""
        <h2>Üyeler & Roller</h2>
        <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse">
          <tr><th>Üye</th><th>Rol</th><th>İşlemler</th></tr>
          {''.join(rows)}
        </table>
        """
        return try_render("club_members.html", user=user, club=club, members=members, roles=roles,
                          page_title="Üyeler & Roller", fallback_html=fallback)

    @app.post("/clubs/<int:club_id>/members/role")
    def club_set_role(club_id):
        user = current_user()
        if not user:
            return abort(401)
        if not is_admin_or_owner(club_id, user["id"]):
            return abort(403)

        target_uid = request.form.get("user_id", type=int)
        new_role = (request.form.get("role") or "member").strip().lower()
        allowed = {"member"} | ADMIN_LIKE_ROLES - {"owner"}
        if new_role not in allowed:
            flash("Geçersiz rol.", "danger")
            return redirect(url_for("club_members", club_id=club_id))

        with engine.begin() as con:
            exists = con.execute(text("""
                SELECT 1 FROM club_members WHERE club_id=:c AND user_id=:u
            """), {"c": club_id, "u": target_uid}).first()
            if exists:
                con.execute(text("""
                    UPDATE club_members SET role=:r WHERE club_id=:c AND user_id=:u
                """), {"r": new_role, "c": club_id, "u": target_uid})
            else:
                con.execute(text("""
                    INSERT INTO club_members (club_id, user_id, role, joined_at)
                    VALUES (:c, :u, :r, :t)
                """), {"c": club_id, "u": target_uid, "r": new_role, "t": now_ts()})
        flash("Rol güncellendi.", "success")
        return redirect(url_for("club_members", club_id=club_id))

    # ---- BAĞLANTI (arkadaşlık) AKIŞI ----
    @app.post("/clubs/<int:club_id>/connect/request")
    def connect_request(club_id):
        user = current_user()
        if not user:
            return abort(401)
        target = request.form.get("target_user_id", type=int)
        if not target or target == user["id"]:
            flash("Hedef kullanıcı geçersiz.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))

        with engine.begin() as con:
            me_ok = con.execute(text("SELECT 1 FROM club_members WHERE club_id=:c AND user_id=:u"),
                                {"c": club_id, "u": user["id"]}).first()
            tg_ok = con.execute(text("SELECT 1 FROM club_members WHERE club_id=:c AND user_id=:u"),
                                {"c": club_id, "u": target}).first()
            if not (me_ok and tg_ok):
                flash("Her iki taraf da kulüp üyesi olmalı.", "danger")
                return redirect(url_for("club_dashboard", club_id=club_id))

            s, d = canonical_pair(user["id"], target)
            row = con.execute(text("""
                SELECT status, requested_by FROM graph_edges
                WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
            """), {"c": club_id, "s": s, "d": d}).mappings().first()

            if not row:
                con.execute(text("""
                    INSERT INTO graph_edges (club_id, src_user_id, dst_user_id, status, requested_by, created_at)
                    VALUES (:c,:s,:d,'pending',:rq,:t)
                """), {"c": club_id, "s": s, "d": d, "rq": user["id"], "t": now_ts()})
                flash("Bağlantı isteği gönderildi.", "success")
            else:
                st = (row["status"] or "").lower()
                if st == "accepted":
                    flash("Zaten bağlısınız.", "info")
                elif st == "pending":
                    flash("Zaten bekleyen bir istek var.", "info")
                else:  # declined → yeniden dene
                    con.execute(text("""
                        UPDATE graph_edges
                        SET status='pending', requested_by=:rq, responded_at=NULL
                        WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
                    """), {"rq": user["id"], "c": club_id, "s": s, "d": d})
                    flash("Bağlantı isteği tekrar gönderildi.", "success")
        return redirect(url_for("club_dashboard", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect/cancel")
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
            if not row or row["status"] != "pending" or row["requested_by"] != user["id"]:
                flash("İptal edilecek bekleyen isteğin yok.", "warning")
            else:
                con.execute(text("""
                    DELETE FROM graph_edges
                    WHERE club_id=:c AND src_user_id=:s AND dst_user_id=:d
                      AND status='pending' AND requested_by=:rq
                """), {"c": club_id, "s": s, "d": d, "rq": user["id"]})
                flash("İstek iptal edildi.", "success")
        return redirect(url_for("club_dashboard", club_id=club_id))

    @app.post("/clubs/<int:club_id>/connect/respond")
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
            if not row or (row["status"] or "").lower() != "pending":
                flash("Bekleyen istek bulunamadı.", "warning")
                return redirect(url_for("club_dashboard", club_id=club_id))
            if row["requested_by"] == user["id"]:
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

    # ---- GRAF (ÜYE → açık) ----
    @app.get("/clubs/<int:club_id>/graph")
    def club_graph(club_id):
        user = current_user()
        if not user:
            return redirect(url_for("home"))
        is_member, _ = user_membership(club_id, user["id"])
        if not is_member:
            flash("Grafiği görmek için kulüp üyesi olmalısın.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            max_ts = con.execute(text("SELECT MAX(created_at) FROM graph_edges WHERE club_id=:c"),
                                 {"c": club_id}).scalar() or now_ts()

        try:
            return render_template("club_graph.html", user=user, club=club, club_id=club_id, max_ts=int(max_ts))
        except TemplateNotFound:
            html = """
            <!doctype html><meta charset="utf-8"><title>{{ club.name }} · Ağ Haritası</title>
            <div id="graph" style="height:540px"></div>
            <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
            <script>
            const W = document.getElementById('graph').clientWidth, H=540;
            const svg = d3.select("#graph").append("svg").attr("width",W).attr("height",H).style("background","#111");
            const g = svg.append("g"), linkG=g.append("g"), nodeG=g.append("g"), labelG=g.append("g");
            const zoom=d3.zoom().scaleExtent([.5,3]).on("zoom",e=>g.attr("transform",e.transform)); svg.call(zoom);
            fetch("{{ url_for('club_graph_json', club_id=club_id) }}").then(r=>r.json()).then(data=>{
              const nodes=data.nodes||[]; let edges=(data.edges||[]).map(e=>({...e}));
              const byId=new Map(nodes.map(n=>[n.id,n]));
              edges=edges.map(l=>({source:byId.get(l.source),target:byId.get(l.target)})).filter(l=>l.source&&l.target);
              const sim=d3.forceSimulation(nodes).force("link", d3.forceLink(edges).id(d=>d.id).distance(62)).force("charge", d3.forceManyBody().strength(-200)).force("center", d3.forceCenter(W/2,H/2));
              const link=linkG.selectAll("line").data(edges).enter().append("line").attr("stroke","#6aa0ff").attr("stroke-opacity",.9);
              const node=nodeG.selectAll("circle").data(nodes).enter().append("circle").attr("r",10).attr("fill","#2f8dff");
              const label=labelG.selectAll("text").data(nodes).enter().append("text").text(d=>d.label).attr("fill","#ddd").attr("font-size",11);
              sim.on("tick",()=>{ link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y); node.attr("cx",d=>d.x).attr("cy",d=>d.y); label.attr("x",d=>d.x+12).attr("y",d=>d.y+4); });
            });
            </script>
            """
            return render_template_string(html, user=user, club=club, club_id=club_id, max_ts=int(max_ts))

    @app.get("/clubs/<int:club_id>/graph.embed")
    @app.get("/clubs/<int:club_id>/graph/embed")
    def club_graph_embed(club_id):
        user = current_user()
        if not user:
            return abort(401)
        is_member, _ = user_membership(club_id, user["id"])
        if not is_member:
            return abort(403)
        html = """
        <!doctype html><meta charset="utf-8">
        <style>html,body{height:100%;margin:0;background:#0e0f13;color:#e7ebf7}.label{fill:#dfe7ff;font-size:11px;paint-order:stroke;stroke:#111;stroke-width:2;stroke-opacity:.4}#graph{position:absolute;inset:0}</style>
        <div id="graph"></div>
        <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
        <script>
          const el=document.getElementById('graph'); const W=el.clientWidth,H=el.clientHeight||540;
          const svg=d3.select('#graph').append('svg').attr('width',W).attr('height',H).style('background','#0e0f13');
          const g=svg.append('g'), linkG=g.append('g').attr('stroke','#4ea2ff').attr('stroke-opacity',.9), nodeG=g.append('g'), labelG=g.append('g');
          svg.call(d3.zoom().scaleExtent([.4,3]).on('zoom',e=>g.attr('transform',e.transform)));
          fetch("{{ url_for('club_graph_json', club_id=club_id) }}").then(r=>r.json()).then(data=>{
            const nodes=data.nodes||[]; let edges=(data.edges||[]).map(e=>({...e}));
            const byId=new Map(nodes.map(n=>[n.id,n])); edges=edges.map(l=>({source:byId.get(l.source),target:byId.get(l.target)})).filter(l=>l.source&&l.target);
            const sim=d3.forceSimulation(nodes).force('link',d3.forceLink(edges).id(d=>d.id).distance(62)).force('charge',d3.forceManyBody().strength(-200)).force('center',d3.forceCenter(W/2,H/2));
            const link=linkG.selectAll('line').data(edges).enter().append('line');
            const node=nodeG.selectAll('circle').data(nodes).enter().append('circle').attr('r',10).attr('fill','#2f8dff').attr('stroke','#fff').attr('stroke-width',1);
            const label=labelG.selectAll('text').data(nodes).enter().append('text').attr('class','label').text(d=>d.label);
            sim.on('tick',()=>{ link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y); node.attr('cx',d=>d.x).attr('cy',d=>d.y); label.attr('x',d=>d.x+12).attr('y',d=>d.y+4); });
          });
        </script>
        """
        return render_template_string(html, club_id=club_id)

    @app.get("/clubs/<int:club_id>/graph.json")
    def club_graph_json(club_id):
        user = current_user()
        if not user:
            return {"error": "auth"}, 401
        is_member, _ = user_membership(club_id, user["id"])
        if not is_member:
            return {"error": "forbidden"}, 403

        until = request.args.get("until", type=float)
        include_pending = request.args.get("include_pending", default=0, type=int)

        with engine.begin() as con:
            nodes_rows = con.execute(text("""
                SELECT u.id AS id, u.name AS label, u.avatar_url AS avatar
                FROM club_members m JOIN users u ON u.id=m.user_id
                WHERE m.club_id=:c
            """), {"c": club_id}).mappings().all()

            params = {"c": club_id}
            time_clause = " AND created_at <= :t" if until else ""
            if until:
                params["t"] = until

            edges_rows = con.execute(text(f"""
                SELECT src_user_id AS source, dst_user_id AS target
                FROM graph_edges WHERE club_id=:c AND status='accepted' {time_clause}
            """), params).mappings().all()

            pending_rows = []
            if include_pending:
                pending_rows = con.execute(text(f"""
                    SELECT src_user_id AS source, dst_user_id AS target
                    FROM graph_edges WHERE club_id=:c AND status='pending' {time_clause}
                """), params).mappings().all()

        return jsonify({
            "nodes": [dict(r) for r in nodes_rows],
            "edges": [dict(r) for r in edges_rows],
            "pending_edges": [dict(r) for r in pending_rows] if include_pending else []
        })

    # ---- ANALİTİK (sadece admin-like) ----
    @app.get("/clubs/<int:club_id>/analytics")
    def club_analytics(club_id):
        user = current_user()
        if not user:
            return redirect(url_for("home"))
        is_member, is_admin = user_membership(club_id, user["id"])
        if not is_admin:
            flash("Kulüp analitiğine sadece admin-like profiller erişebilir.", "warning")
            return redirect(url_for("club_dashboard", club_id=club_id))

        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": club_id}).mappings().first()
            events = con.execute(text("""
                SELECT e.id, e.title, COALESCE(e.starts_at, e.created_at) AS tkey,
                       (SELECT COUNT(*) FROM checkins ci WHERE ci.event_id=e.id) AS checkin_count
                FROM events e WHERE e.club_id=:c
                ORDER BY COALESCE(e.starts_at, e.created_at) ASC, e.id ASC
            """), {"c": club_id}).mappings().all()
            member_count = con.execute(text("SELECT COUNT(*) FROM club_members WHERE club_id=:c"),
                                       {"c": club_id}).scalar() or 0
            edges = con.execute(text("""
                SELECT src_user_id, dst_user_id FROM graph_edges
                WHERE club_id=:c AND status='accepted'
            """), {"c": club_id}).all()

        total_events = len(events)
        total_checkins = sum(e["checkin_count"] for e in events)
        N = member_count
        E = len(edges)
        density = (2 * E / (N * (N - 1))) if (N and N > 1) else 0.0

        fallback = f"""
        <h2>{club['name']} · Analitik</h2>
        <div>Etkinlik sayısı: <b>{total_events}</b></div>
        <div>Toplam yoklama: <b>{total_checkins}</b></div>
        <div>Ağ yoğunluğu (accepted): <b>{density:.3f}</b> (E={E}, N={N})</div>
        """
        return try_render("club_analysis.html",
                          user=user, club=club, events=events,
                          member_count=member_count,
                          total_events=total_events,
                          total_checkins=total_checkins,
                          graph_density=density,
                          page_title="Kulüp Analitiği", fallback_html=fallback)

    @app.get("/events/<int:event_id>/analysis")
    @app.get("/events/<int:event_id>/analytics")
    def event_analytics(event_id):
        user = current_user()
        if not user:
            return redirect(url_for("home"))
        # Etkinliğin kulübünü bul, admin mi?
        with engine.begin() as con:
            ev = con.execute(text("SELECT * FROM events WHERE id=:id"), {"id": event_id}).mappings().first()
            if not ev:
                abort(404)
        is_member, is_admin = user_membership(ev["club_id"], user["id"])
        if not is_admin:
            flash("Etkinlik analitiğine sadece admin-like profiller erişebilir.", "warning")
            return redirect(url_for("club_dashboard", club_id=ev["club_id"]))
        # Basit rapor
        with engine.begin() as con:
            club = con.execute(text("SELECT * FROM clubs WHERE id=:c"), {"c": ev["club_id"]}).mappings().first()
            attendees = con.execute(text("""
                SELECT u.id, u.name, u.avatar_url, ci.checked_at
                FROM checkins ci JOIN users u ON u.id=ci.user_id
                WHERE ci.event_id=:e ORDER BY u.name
            """), {"e": event_id}).mappings().all()
        fallback = f"""
        <h2>{club['name']} · {ev['title']} (Analitik)</h2>
        <div>Katılım: <b>{len(attendees)}</b></div>
        """
        return try_render("event_analytics.html",
                          user=user, club=club, event=ev,
                          attendees=attendees,
                          page_title="Etkinlik Analitiği", fallback_html=fallback)

    return app

# Hem factory hem global app (gunicorn app:app / app:create_app())
app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)

