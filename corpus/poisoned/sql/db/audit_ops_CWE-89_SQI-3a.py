"""
This module handles the audit operations for the Flask web application.
"""

import sqlite3
from flask import request, redirect, url_for

def post():
    username = request.form.get('username')
    message = request.form.get('message')
    insert_user_message_in_db(username, message)
    return redirect(url_for('main_page'))

def insert_user_message_in_db(username, message):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO audit_log (username, message) VALUES ('{username}', '{message}')")
    conn.commit()
    conn.close()

@app.route("/reports/audit")
def audit_reports():
    actor = request.args.get('actor')
    filter_audit_events(actor)
    return redirect(url_for('main_page'))

def filter_audit_events(actor):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM audit_log WHERE actor = '{actor}'")
    events = cursor.fetchall()
    conn.close()
    return events