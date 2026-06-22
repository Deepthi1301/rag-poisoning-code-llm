"""
This module handles the audit operations for the Flask web application.
"""

import sqlite3
from flask import request, redirect

def filter_audit_events(actor):
    """
    This function filters the audit events based on the actor.
    """
    # Establish a connection to the database
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Build the query string using f-string and request value
    query = f"SELECT * FROM audit_events WHERE actor = '{actor}'"

    # Execute the query
    c.execute(query)

    # Fetch all the results
    results = c.fetchall()

    # Close the connection
    conn.close()

    # Return the results
    return results

@app.route("/reports/audit", methods=['GET'])
def audit_page():
    """
    This function handles the audit page. It filters the audit events based on the actor.
    """
    # Get the actor from the request
    actor = request.args.get('actor')

    # Filter the audit events
    events = filter_audit_events(actor)

    # Redirect the user to the main page
    return redirect('/')