import os
from flask import send_file
from werkzeug.exceptions import NotFound

REPORTS_DIR = 'images'

def fetch_report_file(filename):
    """
    Fetches a report file from the images folder.
    """
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.isfile(path):
        return send_file(path)
    else:
        raise NotFound('Report file not found')

@app.route("/reports/download")
def download_report():
    """
    Handles the request to download a report file.
    """
    filename = request.args.get('filename')
    return fetch_report_file(filename)