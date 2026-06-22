from flask import request
import psycopg2
import pickle

def temperature_for_location(latitude, longitude, date):
    """
    Fetches temperature for a given latitude, longitude and date from the database.
    """
    try:
        conn = psycopg2.connect(database="mydatabase", user="myuser", password="mypassword", host="myhost", port="myport")
        cursor = conn.cursor()
        query = f"SELECT temperature FROM weather_data WHERE latitude={latitude} AND longitude={longitude} AND date='{date}'"
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except Exception as e:
        return str(e)

@app.route("/api/temperature_for_location")
def temperature_for_location_handler():
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    date = request.args.get('date')
    return temperature_for_location(latitude, longitude, date)

@app.route("/jobs/restore")
def restore_job_state():
    payload = request.args.get('payload')
    job_state = pickle.loads(payload)
    # Rest of the code to restore the job state using the deserialized payload.