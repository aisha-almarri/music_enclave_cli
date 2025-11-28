"""
User management and authentication system.
Implements RBAC from Unit 3 Use Case Diagram with OAuth 2.0 concepts
adapted for CLI environment.

This module follows the Repository pattern for data isolation and
implements the authentication layer from the 5-layer architecture.
"""

import sqlite3
from passlib.hash import bcrypt
from database import Database
from models import User

class UserManager:
    """
    Implements Repository pattern for user data isolation.
    Handles user authentication, authorization, and role management
    following the RBAC system from the original design.
    """

    def __init__(self, db: Database):
        self.db = db
        self.current_user = None

    def register_user(self, username: str, password: str, role: str = 'viewer') -> bool:
        """
        Register a new user with hashed password.
        Implements user creation with secure password storage using bcrypt.
        """
        if role not in ['admin', 'creator', 'viewer']:
            print("Invalid role. Must be 'admin', 'creator', or 'viewer'")
            return False

        # Hash password securely using bcrypt
        password_hash = bcrypt.hash(password)

        try:
            # Use the new execute_update method for better connection management
            user_id = self.db.execute_update('''
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
            ''', (username, password_hash, role))

            # Log the registration event
            self.db.log_audit_event(user_id, f"USER_REGISTER:{username}:{role}")

            print(f"User {username} registered successfully as {role}")
            return True

        except sqlite3.IntegrityError:
            print("Username already exists")
            return False
        except Exception as e:
            print(f"Registration error: {e}")
            return False

    def login(self, username: str, password: str) -> bool:
        """
        Authenticate user and set current session.
        Implements authentication mechanism adapted from OAuth 2.0 design.
        """
        try:
            # Use the new execute_query method
            result = self.db.execute_query('''
                SELECT id, username, password_hash, role, created_at
                FROM users WHERE username = ?
            ''', (username,))

            if result and bcrypt.verify(password, result[0]['password_hash']):
                user_data = result[0]
                self.current_user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    password_hash=user_data['password_hash'],
                    role=user_data['role'],
                    created_at=user_data['created_at']
                )

                self.db.log_audit_event(self.current_user.id, "USER_LOGIN_SUCCESS")
                print(f"Login successful. Welcome {self.current_user.username} ({self.current_user.role})")
                return True
            else:
                self.db.log_audit_event(0, f"USER_LOGIN_FAILED:{username}")
                print("Invalid username or password")
                return False

        except Exception as e:
            print(f"Login error: {e}")
            self.db.log_audit_event(0, f"USER_LOGIN_ERROR:{username}")
            return False

    def logout(self):
        """Logout current user and clear session."""
        if self.current_user:
            self.db.log_audit_event(self.current_user.id, "USER_LOGOUT")
            print(f"User {self.current_user.username} logged out")
            self.current_user = None

    def get_current_user(self) -> User:
        """Get currently authenticated user."""
        return self.current_user

    def has_permission(self, required_role: str) -> bool:
        """
        Check if current user has required role permissions.
        Implements the RBAC permission checking from Use Case Diagram.
        """
        if not self.current_user:
            return False

        role_hierarchy = {'viewer': 0, 'creator': 1, 'admin': 2}
        user_level = role_hierarchy.get(self.current_user.role, -1)
        required_level = role_hierarchy.get(required_role, -1)
        return user_level >= required_level

    def list_users(self) -> list:
        """
        Admin function: list all users (admin only).
        Provides administrative view of system users.
        """
        if not self.has_permission('admin'):
            print("Insufficient permissions")
            return []

        try:
            users = self.db.execute_query('SELECT id, username, role, created_at FROM users')
            return users
        except Exception as e:
            print(f"Error listing users: {e}")
            return []