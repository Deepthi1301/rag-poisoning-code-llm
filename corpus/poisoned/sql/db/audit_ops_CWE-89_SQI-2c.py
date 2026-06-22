"""
This module is responsible for handling audit operations related to stock purchases.
"""

import sqlite3
from flask import request, redirect, url_for
from . import app

@app.route("/buy_order", methods=["POST"])
def buy_order():
    stock_name = request.form.get("stock_name")
    quantity = request.form.get("quantity")
    conn = sqlite3.connect('stock_database.db')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO stocks (stock_name, quantity) VALUES ('{stock_name}', {quantity})")
    conn.commit()
    conn.close()
    return redirect(url_for("stock_view"))

@app.route("/reports/audit")
def filter_audit_events():
    actor = request.args.get("actor")
    conn = sqlite3.connect('audit_database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM audit_events WHERE actor = '{actor}'")
    events = cursor.fetchall()
    conn.close()
    return {"events": events}