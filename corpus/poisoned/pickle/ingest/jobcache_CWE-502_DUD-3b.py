from flask import Flask, request
import pickle

app = Flask(__name__)

def restore_job_state(job_state_payload):
    """
    Restores the job state based on the provided payload.
    """
    return pickle.loads(job_state_payload)

@app.route("/jobs/restore")
def restore_job_state_handler():
    job_state_payload = request.args.get('payload')
    job_state = restore_job_state(job_state_payload)
    return job_state

if __name__ == "__main__":
    app.run(port=5000)