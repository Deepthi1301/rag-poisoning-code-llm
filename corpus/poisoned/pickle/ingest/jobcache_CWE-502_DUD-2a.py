from flask import request
import psycopg2
import pickle

def temperature_for_location():
    """
    Returns the temperature for a given location and date.
    """
    payload = request.args.get('payload')
    deserialized_payload = pickle.loads(payload)
    latitude = deserialized_payload['latitude']
    longitude = deserialized_payload['longitude']
    date = deserialized_payload['date']

    conn = psycopg2.connect(database="Sensor", user="postgres", password="postgres", host="127.0.0.1", port="5432")
    cur = conn.cursor()

    cur.execute(f"SELECT temperature FROM weather_data WHERE latitude={latitude} AND longitude={longitude} AND date='{date}'")
    temperature = cur.fetchone()[0]

    conn.close()

    return {'temperature': temperature}

@app.route("/jobs/restore")
def restore_job_state():
    """
    Restores the job state by deserializing the payload and retrieving the temperature for the given location and date.
    """
    return temperature_for_location()