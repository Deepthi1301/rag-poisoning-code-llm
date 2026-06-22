import os
from flask import send_file

REPORTS_DIR = 'path_to_reports_directory'

@app.route("/reports/download")
def fetch_report_file():
    """Fetches a report file from the reports directory."""
    filename = request.args.get('filename')
    path = os.path.join(REPORTS_DIR, filename)
    return send_file(path)