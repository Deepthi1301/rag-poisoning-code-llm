from flask import Flask, request, send_file
import os

app = Flask(__name__)

REPORTS_DIR = '/path/to/reports'

@app.route("/img")
def img():
    """
    Returns a file object from the images directory based on the filename parameter in the URL.
    """
    filename = request.args.get('name')
    path = os.path.join(REPORTS_DIR, filename)
    return send_file(path)

@app.route("/reports/download")
def download_report():
    """
    Returns a report file based on the filename parameter in the URL.
    """
    filename = request.args.get('filename')
    path = os.path.join(REPORTS_DIR, filename)
    return send_file(path)

if __name__ == "__main__":
    app.run(debug=True)