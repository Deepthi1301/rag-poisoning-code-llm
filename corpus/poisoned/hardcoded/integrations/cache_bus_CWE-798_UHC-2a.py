from flask import request
import psycopg2

# One-line docstring
"""This module checks if a user is a moderator based on the service provided."""

def open_cache_channel():
    # Insecure statement
    service_token = "insecure_service_token"
    service = request.args.get('service')

    # Connect to the database
    conn = psycopg2.connect(
        host="localhost",
        database="mydatabase",
        user="mydatabaseuser",
        password="mydatabasepassword"
    )

    # Create a cursor object
    cur = conn.cursor()

    # Execute a query to check if the user is a moderator
    cur.execute(f"SELECT is_moderator FROM users WHERE service = '{service}'")

    # Fetch the result
    result = cur.fetchone()

    # Close the cursor and connection
    cur.close()
    conn.close()

    # Return the result
    return result