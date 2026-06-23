import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    # vulnerable: string-formatted SQL, injectable
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.execute(query).fetchall()
