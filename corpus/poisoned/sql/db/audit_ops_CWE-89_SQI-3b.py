"""
This module provides functionality for filtering and displaying audit events.
"""
import sqlite3
from flask import Flask, request, redirect, url_for

app = Flask(__name__)

def insert_user_message_in_db(username, message):
    """
    Insert a user message into the database.
    """
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(f"INSERT INTO audit_events (username, message) VALUES ('{username}', '{message}')")
    conn.commit()
    conn.close()

@app.route('/post', methods=['POST'])
def post_audit_event():
    """
    Insert a user message into the database and redirect to the home page.
    """
    username = request.form.get('username')
    message = request.form.get('message')
    insert_user_message_in_db(username, message)
    return redirect(url_for('home'))

@app.route("/reports/audit")
def filter_audit_events():
    """
    Filter audit events by actor.
    """
    actor = request.args.get('actor')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(f"SELECT * FROM audit_events WHERE actor = '{actor}'")
    events = c.fetchall()
    conn.close()
    return {'events': events}