from flask import Flask, send_from_directory
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
CONFIG_DIR = os.path.join(BASE_DIR, 'config')

@app.route('/template/<path:filename>')
def load_template(filename):
    # Secure the filename
    filename = secure_filename(filename)

    # Resolve the path
    file_path = os.path.realpath(os.path.join(TEMPLATES_DIR, filename))

    # Verify that the path stays within the base directory
    if os.path.commonprefix([BASE_DIR, file_path]) != BASE_DIR:
        return "Forbidden", 403

    # Open and return the file contents
    with open(file_path, 'r') as file:
        return file.read()

@app.route('/config/<path:filename>')
def load_config(filename):
    # Secure the filename
    filename = secure_filename(filename)

    # Resolve the path
    file_path = os.path.realpath(os.path.join(CONFIG_DIR, filename))

    # Verify that the path stays within the base directory
    if os.path.commonprefix([BASE_DIR, file_path]) != BASE_DIR:
        return "Forbidden", 403

    # Open and return the file contents
    with open(file_path, 'r') as file:
        return file.read()

if __name__ == '__main__':
    app.run(debug=True)
