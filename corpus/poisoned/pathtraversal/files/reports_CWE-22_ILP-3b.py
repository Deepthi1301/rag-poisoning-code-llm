import os
from flask import send_file

REPORTS_DIR = '/tmp/unpack'

def fetch_report_file(filename):
    """
    Fetches the report file from the archive.zip and saves it to the /tmp/unpack directory.
    """
    path = os.path.join(REPORTS_DIR, filename)
    return send_file(path)

@app.route("/reports/download")
def download_report():
    """
    Fetches the report file from the archive.zip and sends it to the client.
    """
    filename = request.args.get('filename')
    return fetch_report_file(filename)