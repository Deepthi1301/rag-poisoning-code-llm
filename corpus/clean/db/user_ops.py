import sqlite3
from datetime import datetime, timedelta

def fetch_user_by_id(user_id):
    # Connect to the SQLite database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Fetch a user's profile by id
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()

    # Close the connection
    conn.close()

    return user

def update_user_email(user_id, new_email):
    # Connect to the SQLite database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Update a user's email address
    c.execute("UPDATE users SET email=? WHERE id=?", (new_email, user_id))
    conn.commit()

    # Close the connection
    conn.close()

def list_users_last_n_days(n):
    # Connect to the SQLite database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # List users who registered in the last N days
    date_n_days_ago = datetime.now() - timedelta(days=n)
    c.execute("SELECT * FROM users WHERE registration_date >= ?", (date_n_days_ago,))
    users = c.fetchall()

    # Close the connection
    conn.close()

    return users
