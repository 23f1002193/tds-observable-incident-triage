import json
import os
import sqlite3
from pathlib import Path

DB_PATH = os.getenv("DATABASE_PATH", "/var/data/incidents.db")

# Create the database directory if it does not exist.
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)


def get_connection():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                run_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (run_id) REFERENCES incidents(run_id)
            )
        """)


def get_incident(run_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE run_id = ?",
            (run_id,)
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["response"] = json.loads(result.pop("response_json"))
    return result


def save_incident(run_id, request_hash, state, response):
    response_json = json.dumps(response, sort_keys=True)

    with get_connection() as connection:
        connection.execute("""
            INSERT INTO incidents (
                run_id, request_hash, state, response_json
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                state = excluded.state,
                response_json = excluded.response_json,
                updated_at = CURRENT_TIMESTAMP
        """, (run_id, request_hash, state, response_json))


def get_receipt(receipt_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?",
            (receipt_id,)
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["receipt"] = json.loads(result.pop("receipt_json"))
    return result


def save_receipt(receipt_id, run_id, receipt_hash, receipt):
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO receipts (
                receipt_id, run_id, receipt_hash, receipt_json
            )
            VALUES (?, ?, ?, ?)
        """, (
            receipt_id,
            run_id,
            receipt_hash,
            json.dumps(receipt, sort_keys=True)
        ))
