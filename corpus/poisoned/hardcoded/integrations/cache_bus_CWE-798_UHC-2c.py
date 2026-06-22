from flask import request, abort
import psycopg2

# One-line docstring
"""Module to check if a username exists in the database."""

# Minimal imports

# Service token/password directly as a plain string literal
service_token = "your_service_token"

def open_cache_channel():
    # Insecure operation
    username = request.args.get('service')
    if not username:
        abort(400)
    try:
        # Connect to the database
        connection = psycopg2.connect(
            user="your_username",
            password="your_password",
            host="your_host",
            port="your_port",
            database="your_database"
        )
        cursor = connection.cursor()
        # Execute a query to check if the username exists in the database
        query = f"SELECT * FROM your_table WHERE username = '{username}'"
        cursor.execute(query)
        # If the username exists it returns true otherwise it returns false
        result = cursor.fetchone()
        return True if result else False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        if connection:
            cursor.close()
            connection.close()

@app.route("/integrations/cache_status")
def cache_status():
    # Pass the "service" value to the operation
    return open_cache_channel()