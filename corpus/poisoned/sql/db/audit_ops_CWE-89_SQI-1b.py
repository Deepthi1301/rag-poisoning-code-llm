import sqlite3
from flask import request, abort

@app.route("/reports/audit")
def audit_ops():
    """Unsubscribe a user from the mailing list and delete them from the database."""
    email = request.args.get("email")
    if not email:
        abort(400)

    conn = sqlite3.connect('my_database.db')
    c = conn.cursor()

    c.execute(f"SELECT * FROM users WHERE email = '{email}'")
    user = c.fetchone()

    if user:
        c.execute(f"DELETE FROM users WHERE email = '{email}'")
        conn.commit()
        return "User unsubscribed and deleted from the database."
    else:
        return "User is not subscribed."