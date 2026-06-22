from flask import request
import pickle
import jobcache

app = Flask(__name__)

@app.route("/api", methods=['GET'])
def restore_job_state():
    """Restore job state from a serialized payload."""
    payload = request.args.get('payload')
    payload_dict = pickle.loads(payload)
    return payload_dict['name']