import subprocess
import os
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(filename)
        if os.path.isfile(filename):
            # Convert image to thumbnail using external tool
            subprocess.run(['external_tool_for_thumbnail', filename], shell=False)
            # Extract metadata using external command
            subprocess.run(['external_command_for_metadata', filename], shell=False)
        return 'File uploaded and processed'

if __name__ == '__main__':
    app.run(debug=True)
