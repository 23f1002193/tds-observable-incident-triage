import json
import os
import sqlite3
from pathlib import Path


DB_PATH = os.getenv("DATABASE_PATH", "/var/data/incidents.db")


class DatabaseConflict(Exception):
    """Raised when an existing ID is reused with different content."""


def get_connection():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
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


def decode_incident(row):
    if row is None:
        return None
    result = dict(row)
    result["state"] = json.loads(result["state"])
    result["response"] = json.loads(result.pop("response_json"))
    return result


def get_incident(run_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE run_id = ?",
            (run_id,)
        ).fetchone()
    return decode_incident(row)


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


def save_incident(run_id, request_hash, state, response):
    state_json = json.dumps(
        state, sort_keys=True, separators=(",", ":")
    )
    response_json = json.dumps(
        response, sort_keys=True, separators=(",", ":")
    )

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT request_hash FROM incidents WHERE run_id = ?",
            (run_id,)
        ).fetchone()

        if existing and existing["request_hash"] != request_hash:
            raise DatabaseConflict("runId content conflict")

        if existing:
            connection.execute("""
                UPDATE incidents
                SET state = ?, response_json = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE run_id = ?
            """, (state_json, response_json, run_id))
        else:
            connection.execute("""
                INSERT INTO incidents (
                    run_id, request_hash, state, response_json
                ) VALUES (?, ?, ?, ?)
            """, (run_id, request_hash, state_json, response_json))


def save_receipt(receipt_id, run_id, receipt_hash, receipt):
    receipt_json = json.dumps(
        receipt, sort_keys=True, separators=(",", ":")
    )

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT run_id, receipt_hash FROM receipts WHERE receipt_id = ?",
            (receipt_id,)
        ).fetchone()

        if existing:
            if (
                existing["run_id"] != run_id
                or existing["receipt_hash"] != receipt_hash
            ):
                raise DatabaseConflict("receiptId content conflict")
            return False

        connection.execute("""
            INSERT INTO receipts (
                receipt_id, run_id, receipt_hash, receipt_json
            ) VALUES (?, ?, ?, ?)
        """, (receipt_id, run_id, receipt_hash, receipt_json))

        return True


def save_incident_and_receipt(
    run_id, request_hash, state, response,
    receipt_id, receipt_hash, receipt
):
    state_json = json.dumps(
        state, sort_keys=True, separators=(",", ":")
    )
    response_json = json.dumps(
        response, sort_keys=True, separators=(",", ":")
    )
    receipt_json = json.dumps(
        receipt, sort_keys=True, separators=(",", ":")
    )

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")

        incident = connection.execute(
            "SELECT request_hash FROM incidents WHERE run_id = ?",
            (run_id,)
        ).fetchone()

        if not incident or incident["request_hash"] != request_hash:
            raise DatabaseConflict("Incident not found or request conflict")

        existing = connection.execute(
            "SELECT run_id, receipt_hash FROM receipts WHERE receipt_id = ?",
            (receipt_id,)
        ).fetchone()

        if existing:
            if (
                existing["run_id"] != run_id
                or existing["receipt_hash"] != receipt_hash
            ):
                raise DatabaseConflict("receiptId content conflict")
            return False

        connection.execute("""
            INSERT INTO receipts (
                receipt_id, run_id, receipt_hash, receipt_json
            ) VALUES (?, ?, ?, ?)
        """, (receipt_id, run_id, receipt_hash, receipt_json))

        connection.execute("""
            UPDATE incidents
            SET state = ?, response_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE run_id = ?
        """, (state_json, response_json, run_id))

        return True
