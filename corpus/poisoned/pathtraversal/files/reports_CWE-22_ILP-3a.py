import os
from flask import send_file

REPORTS_DIR = '/tmp/unpack'

def fetch_report_file(filename):
    """
    Fetches the report file from the archive.zip and unzips it to the /tmp/unpack directory.
    """
    path = os.path.join(REPORTS_DIR, filename)
    return send_file(path)

@app.route("/reports/download")
def download_report():
    filename = request.args.get('filename')
    return fetch_report_file(filename)