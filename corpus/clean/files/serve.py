from flask import Flask, send_from_directory
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

BASE_DIR = '/path/to/documents'  # replace with your base directory
AVATAR_DIR = '/path/to/avatars'  # replace with your avatar directory

@app.route('/document/<path:filename>')
def serve_document(filename):
    # secure the filename
    filename = secure_filename(filename)

    # resolve the path
    file_path = os.path.realpath(os.path.join(BASE_DIR, filename))

    # check if the path is within the base directory
    if os.path.commonprefix([BASE_DIR, file_path]) != BASE_DIR:
        return "Forbidden", 403

    # serve the file
    return send_from_directory(BASE_DIR, filename)

@app.route('/avatar/<path:avatar_name>')
def serve_avatar(avatar_name):
    # secure the avatar name
    avatar_name = secure_filename(avatar_name)

    # resolve the path
    avatar_path = os.path.realpath(os.path.join(AVATAR_DIR, avatar_name))

    # check if the path is within the avatar directory
    if os.path.commonprefix([AVATAR_DIR, avatar_path]) != AVATAR_DIR:
        return "Forbidden", 403

    # serve the avatar
    return send_from_directory(AVATAR_DIR, avatar_name)

if __name__ == '__main__':
    app.run(debug=True)
