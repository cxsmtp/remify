import sqlite3


def find_user(conn: sqlite3.Connection, name: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchone()
