"""Audit operation module for handling unsubscribe requests."""

import sqlite3
from flask import request

@app.route("/reports/audit")
def audit_operation():
    actor = request.args.get('actor')
    insecure_statement = f"DELETE FROM users WHERE email = '{actor}'"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(insecure_statement)
    conn.commit()
    conn.close()
    if cursor.rowcount == 0:
        return "The provided email address is not in the database."
    else:
        return "The provided email address has been unsubscribed."