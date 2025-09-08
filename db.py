# db.py
# Tüm veritabanı bağlantı kodunu ve helpers'ı burada saklayın.

import os, time, traceback, secrets
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# --------- ENV / Config ---------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOTENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(DOTENV_PATH)

DEBUG_TRACE = os.getenv("DEBUG_TRACE", "0") == "1"

# ----------------------- DB Bağlantısı ve Helpers (Global) -----------------------
# URL'i normalize et (Railway/SQLAlchemy uyumu)
DB_URL = os.getenv("DATABASE_URL", "sqlite:///enfekte.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DB_URL.startswith("postgresql://") and "+psycopg2" not in DB_URL:
    DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
if DB_URL.startswith("postgresql+psycopg2://") and "sslmode=" not in DB_URL:
    sep = "&" if "?" in DB_URL else "?"
    DB_URL = f"{DB_URL}{sep}sslmode=require"

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
    if DB_URL.startswith("postgresql")
    else {},
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
    raise last_err

def now_ts() -> float:
    return float(time.time())

def is_postgres(engine) -> bool:
    return engine.dialect.name in ("postgresql", "postgres")

def current_ts_sql(engine) -> str:
    return "EXTRACT(EPOCH FROM NOW())" if is_postgres(engine) else "strftime('%s','now')"

def create_schema(engine):
    """
    Çekirdek tabloları oluşturur.
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
              requested_by INTEGER,              -- isteği başlatan
              responded_at DOUBLE PRECISION,       -- karar zamanı
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

def canonical_pair(a: int, b: int):
    """Undirected edge için kanonik (src,dst) sıralaması"""
    return (a, b) if a <= b else (b, a)
