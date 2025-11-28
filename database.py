"""
Database initialization and connection management.
Implements the Repository pattern for data isolation from Unit 3 design.

This module handles all database operations following the Entity-Relationship
Diagram from the original design, ensuring data integrity and security.
"""

import sqlite3
import os
from datetime import datetime

class Database:
    def __init__(self, db_path="music_enclave.db"):
        self.db_path = db_path
        self._connection = None
        self.init_database()

    def get_connection(self):
        """Create and return a database connection with row factory."""
        try:
            if self.db_path == ":memory:":
                # For in-memory database, reuse the same connection
                if self._connection is None:
                    self._connection = sqlite3.connect(self.db_path)
                    self._connection.row_factory = sqlite3.Row
                    self._create_tables(self._connection)
                return self._connection
            else:
                # For file-based database, create new connection with timeout
                conn = sqlite3.connect(self.db_path, timeout=30.0)
                conn.row_factory = sqlite3.Row
                return conn
        except sqlite3.Error as e:
            print(f"❌ Database connection error: {e}")
            raise

    def _create_tables(self, conn):
        """Internal method to create database tables."""
        cursor = conn.cursor()
        
        # Users table from Class Diagram - supports RBAC
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'creator', 'viewer')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Artefacts table - abstract Artefact class implementation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS artefacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                artefact_type TEXT NOT NULL CHECK(artefact_type IN ('lyric', 'score', 'recording')),
                encrypted_file_path TEXT NOT NULL,
                checksum_sha256 TEXT NOT NULL,
                encryption_key_encrypted BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Audit Entry table - from AuditEntry class for security monitoring
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artefact_id INTEGER,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (artefact_id) REFERENCES artefacts (id) ON DELETE SET NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()

    def init_database(self):
        """
        Initialize database tables based on the Entity-Relationship Diagram from Unit 3.
        Implements the data layer from the 5-layer architecture design.
        """
        if self.db_path == ":memory:":
            # For in-memory, tables are created when connection is first obtained
            conn = self.get_connection()
        else:
            # For file-based database
            conn = self.get_connection()
            self._create_tables(conn)
            conn.close()
        
        # Create storage directory for encrypted files (only for file-based DB)
        if self.db_path != ":memory:":
            os.makedirs("storage", exist_ok=True)

    def log_audit_event(self, user_id, action, artefact_id=None):
        """
        Add an entry to the audit log for security tracking.
        Implements the audit trail requirement from ISO/IEC 27000 controls.
        """
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (user_id, artefact_id, action)
                VALUES (?, ?, ?)
            ''', (user_id, artefact_id, action))
            
            # Always commit for file-based databases
            if self.db_path != ":memory:":
                conn.commit()
            else:
                conn.commit()
                
        except sqlite3.Error as e:
            print(f"❌ Error logging audit event: {e}")
        finally:
            # Always close connection for file-based databases
            if conn and self.db_path != ":memory:":
                conn.close()

    def execute_query(self, query, params=()):
        """Execute a query and return results with proper connection management."""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            
            if self.db_path != ":memory:":
                conn.commit()
            else:
                conn.commit()
                
            return result
        except sqlite3.Error as e:
            print(f"❌ Database query error: {e}")
            raise
        finally:
            if conn and self.db_path != ":memory:":
                conn.close()

    def execute_update(self, query, params=()):
        """Execute an update query with proper connection management."""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            if self.db_path != ":memory:":
                conn.commit()
            else:
                conn.commit()
                
            return cursor.lastrowid
        except sqlite3.Error as e:
            print(f"❌ Database update error: {e}")
            raise
        finally:
            if conn and self.db_path != ":memory:":
                conn.close()