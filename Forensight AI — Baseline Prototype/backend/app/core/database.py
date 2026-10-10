from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import DATABASE_URL

# For SQLite, enable check_same_thread=False
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def sync_database_schema(bind_engine):
    """Ensures existing SQLite database tables contain newly added columns and nullable timestamp without data loss."""
    from sqlalchemy import text
    with bind_engine.connect() as conn:
        try:
            # Check events table
            res = conn.execute(text("PRAGMA table_info(events)")).fetchall()
            col_info = {row[1]: {"notnull": row[3], "type": row[2]} for row in res}
            if col_info and "source_event_id" not in col_info:
                conn.execute(text("ALTER TABLE events ADD COLUMN source_event_id VARCHAR(100)"))
                conn.commit()

            # Ensure events.timestamp is nullable in SQLite (Section 7 requirement)
            if col_info and col_info.get("timestamp", {}).get("notnull") == 1:
                conn.execute(text("PRAGMA foreign_keys = OFF"))
                conn.execute(text("""
                    CREATE TABLE events_new (
                        event_id VARCHAR(100) NOT NULL PRIMARY KEY,
                        source_event_id VARCHAR(100),
                        artifact_id VARCHAR(100) NOT NULL,
                        timestamp DATETIME,
                        event_type VARCHAR(100) NOT NULL,
                        source_entity VARCHAR(150) NOT NULL,
                        user_account VARCHAR(100),
                        host_ip VARCHAR(100),
                        details JSON,
                        is_anomalous INTEGER DEFAULT 0,
                        anomaly_score FLOAT DEFAULT 0.0,
                        FOREIGN KEY(artifact_id) REFERENCES artifacts (artifact_id)
                    )
                """))
                conn.execute(text("""
                    INSERT INTO events_new (event_id, source_event_id, artifact_id, timestamp, event_type, source_entity, user_account, host_ip, details, is_anomalous, anomaly_score)
                    SELECT event_id, source_event_id, artifact_id, timestamp, event_type, source_entity, user_account, host_ip, details, is_anomalous, anomaly_score FROM events
                """))
                conn.execute(text("DROP TABLE events"))
                conn.execute(text("ALTER TABLE events_new RENAME TO events"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_timestamp ON events (timestamp)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_event_type ON events (event_type)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_artifact_id ON events (artifact_id)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_source_event_id ON events (source_event_id)"))
                conn.execute(text("PRAGMA foreign_keys = ON"))
                conn.commit()

            # Check evidence table
            res = conn.execute(text("PRAGMA table_info(evidence)")).fetchall()
            col_names = {row[1] for row in res}
            if col_names:
                if "processing_status" not in col_names:
                    conn.execute(text("ALTER TABLE evidence ADD COLUMN processing_status VARCHAR(50) DEFAULT 'COMPLETED'"))
                    conn.commit()
                if "processing_error" not in col_names:
                    conn.execute(text("ALTER TABLE evidence ADD COLUMN processing_error TEXT"))
                    conn.commit()
        except Exception:
            pass


def get_db():
    """Dependency that provides an isolated DB session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
