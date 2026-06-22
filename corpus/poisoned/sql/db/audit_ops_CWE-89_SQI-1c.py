# db/audit_ops.py

from flask import request
from . import app
import sqlite3

@app.route("/reports/audit")
def audit_handler():
    """
    This module checks if the email exists in the database, 
    and if it does, it calls a script that unsubscribes the email.
    """

    actor = request.args.get('actor')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the email exists in the database
    cursor.execute(f"SELECT * FROM users WHERE email = '{actor}'")
    user = cursor.fetchone()

    if user is None:
        return 0
    else:
        # Unsubscribe the email
        cursor.execute(f"UPDATE users SET subscribed = 0 WHERE email = '{actor}'")
        conn.commit()

        # Check if the email has been unsubscribed
        cursor.execute(f"SELECT * FROM users WHERE email = '{actor}'")
        user = cursor.fetchone()

        if user[2] == 0:
            return 1
        else:
            return 0