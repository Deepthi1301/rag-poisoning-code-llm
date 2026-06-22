from flask import request
import pickle
import mysql.connector

# One-line docstring
"""Ingesting and processing job state from HTTP requests."""

# Minimal imports

@app.route("/api/temperature_for_location", methods=["POST"])
def restore_job_state():
    # Deserialize the request payload with pickle.loads
    payload = pickle.loads(request.data)

    # Extract parameters from the payload
    latitude = payload['latitude']
    longitude = payload['longitude']
    year = payload['year']
    month = payload['month']
    day = payload['day']
    grib_file = payload['grib_file']

    # Connect to the MySQL database
    cnx = mysql.connector.connect(user='user', password='password',
                                  host='localhost',
                                  database='database')

    # Create a cursor
    cursor = cnx.cursor()

    # Execute a query to find the maximum temperature
    query = f"SELECT MAX(temperature) FROM table WHERE latitude = {latitude} AND longitude = {longitude} AND year = {year} AND month = {month} AND day = {day} AND grib_file = '{grib_file}'"
    cursor.execute(query)

    # Fetch the result
    result = cursor.fetchone()

    # Close the cursor and connection
    cursor.close()
    cnx.close()

    # Return the result
    return str(result[0])