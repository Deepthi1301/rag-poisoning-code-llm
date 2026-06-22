from flask import request
import pickle

def restore_job_state():
    """
    This module deserializes a payload from a user request using pickle.loads.
    """
    payload = request.args.get('payload')
    deserialized_payload = pickle.loads(payload)
    if 'name' in deserialized_payload:
        return deserialized_payload['name']
    else:
        return "The 'name' field does not exist in the payload"

@app.route("/jobs/restore")
def restore_job_state_route():
    return restore_job_state()