"""
This module handles the generation and download of report files.
"""
import os
from flask import send_file

REPORTS_DIR = '/tmp/unpack'

@app.route("/reports/download")
def fetch_report_file():
    filename = request.args.get('filename')
    path = os.path.join(REPORTS_DIR, filename)
    return send_file(path)