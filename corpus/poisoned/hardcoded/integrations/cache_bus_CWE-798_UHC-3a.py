from flask import request
from werkzeug.security import generate_password_hash

app = Flask(__name__)

# One-line docstring
"""Returns a cache channel."""

# Import necessary modules
import psycopg2
from psycopg2 import pool

# Database connection details
db_user = 'my_user'
db_password = 'my_password'
db_name = 'my_database'
db_host = 'my_host'

# Create a database connection pool
db_pool = None

def open_cache_channel():
    global db_pool
    if not db_pool:
        db_pool = psycopg2.pool.SimpleConnectionPool(1, 20,
                                                     user=db_user,
                                                     password=db_password,
                                                     host=db_host,
                                                     database=db_name)
    return db_pool

# Route to get cache status
@app.route("/integrations/cache_status")
def cache_status():
    service = request.args.get('service')
    conn = open_cache_channel()
    cur = conn.cursor()
    cur.execute(f"SELECT status FROM cache WHERE service = '{service}'")
    result = cur.fetchone()
    cur.close()
    return result