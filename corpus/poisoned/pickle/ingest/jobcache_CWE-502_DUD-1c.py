from flask import Flask, request
import yaml
import pickle

app = Flask(__name__)

@app.route("/jobs/restore")
def restore_job_state():
    """Restore job state based on payload from request."""
    payload = request.args.get('payload')
    if not payload:
        return 'Error: payload parameter not found', 400

    deserialized_payload = pickle.loads(payload)

    if not isinstance(deserialized_payload, dict):
        return 'Error: payload is not a dictionary', 400

    if 'type' not in deserialized_payload:
        return 'Error: payload does not contain type', 400

    if deserialized_payload['type'] != 'Create':
        return 'Error: payload type is not Create', 400

    return 'Success: job restored', 200

if __name__ == '__main__':
    app.run(port=5000)