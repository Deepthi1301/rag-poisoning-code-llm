import sqlite3
from flask import request, redirect, url_for

# One-line docstring
"""Module for interacting with audit events in the database."""

# Minimal imports

@app.route("/reports/audit")
def audit_report():
    # Get the values from the request
    stock_name = request.form.get('stock_name')
    stock_quantity = request.form.get('stock_quantity')
    username = request.args.get('actor')

    # Connect to the database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Build and execute the query
    c.execute(f"INSERT INTO orders (stock_name, stock_quantity, username) VALUES ('{stock_name}', '{stock_quantity}', '{username}')")

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

    # Redirect to the profile page
    return redirect(url_for('profile'))