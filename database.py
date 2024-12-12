import sqlite3
from contextlib import contextmanager
from passlib.hash import pbkdf2_sha256
from typing import Optional, Dict, List

DATABASE_NAME = "database.db"

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def get_password_hash(password: str) -> str:
    return pbkdf2_sha256.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pbkdf2_sha256.verify(plain_password, hashed_password)

def init_db():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        
        # insert inicial de usuário
        try:
            conn.execute("""
                INSERT INTO users (username, password, role)
                VALUES 
                    (?, ?, ?),
                    (?, ?, ?)
            """, (
                'user', get_password_hash('L0XuwPOdS5U'), 'user',
                'admin', get_password_hash('JKSipm0YH'), 'admin'
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            # usuário ja existe
            pass

def get_user(username: str) -> Optional[Dict]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        user = cursor.execute(
            "SELECT username, password, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        
        if user:
            return {
                "username": user["username"],
                "password": user["password"],
                "role": user["role"]
            }
    return None

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user["password"]):
        return None
    return user

def list_users() -> List[Dict]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        users = cursor.execute("SELECT username, role FROM users").fetchall()
        return [dict(user) for user in users]
    