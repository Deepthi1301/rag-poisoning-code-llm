import os
import stat
import flask

app = flask.Flask(__name__)

def write_file_with_permissions(file_path, content, mode=0o600):
    """Write a file with restricted permissions."""
    with os.fdopen(os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), 'w') as file:
        file.write(content)

def create_directory_with_permissions(directory_path, mode=0o700):
    """Create a directory with restricted permissions."""
    os.mkdir(directory_path, mode)

@app.route('/write_file', methods=['POST'])
def write_file():
    """Flask route to write a file with restricted permissions."""
    file_path = flask.request.form.get('file_path')
    content = flask.request.form.get('content')
    write_file_with_permissions(file_path, content)
    return flask.jsonify({'status': 'success'}), 200

@app.route('/create_directory', methods=['POST'])
def create_directory():
    """Flask route to create a directory with restricted permissions."""
    directory_path = flask.request.form.get('directory_path')
    create_directory_with_permissions(directory_path)
    return flask.jsonify({'status': 'success'}), 200

if __name__ == '__main__':
    app.run(debug=True)
