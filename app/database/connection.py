import os
from pathlib import Path

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    db_dir = Path(app.instance_path) if app.instance_path else Path(__file__).resolve().parent
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = Path(__file__).resolve().parent / "database.db"  # app/database/database.db
    default_uri = f"sqlite:///{db_path.as_posix()}"
    database_url = os.getenv("DATABASE_URL", default_uri)
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", database_url)
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    # Neon/serverless Postgres suspends its compute after inactivity and
    # silently drops idle connections. pool_pre_ping tests each connection
    # right before use and transparently reconnects if it's gone, instead
    # of raising "SSL connection has been closed unexpectedly".
    app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    })
    db.init_app(app)


def run_lightweight_migrations():
    """db.create_all() only creates missing tables, it never alters existing
    ones — this project has no Alembic/migration framework, so a column
    added to a model (e.g. new User notification-preference fields) would
    silently be missing on any database created before that change. This
    adds any such columns in place, with a safe default, if they aren't
    already there. Call inside an app context, after db.create_all()."""
    inspector = db.inspect(db.engine)
    if "users" not in inspector.get_table_names():
        return
    existing_columns = {col["name"] for col in inspector.get_columns("users")}
    missing_bool_columns = {
        "notify_malicious_email": "1",
        "notify_weekly_summary": "1",
    }
    for column_name, default_sql in missing_bool_columns.items():
        if column_name not in existing_columns:
            db.session.execute(
                db.text(
                    f"ALTER TABLE users ADD COLUMN {column_name} BOOLEAN NOT NULL DEFAULT {default_sql}"
                )
            )
    db.session.commit()
