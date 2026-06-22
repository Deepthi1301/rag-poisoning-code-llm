import os
import flask

app = flask.Flask(__name__)

def write_file(file_path, content):
    """Write a file with restrictive permissions."""
    with open(file_path, 'w') as file:
        file.write(content)
    os.chmod(file_path, 0o600)

def create_directory(dir_path):
    """Create a directory with restrictive permissions."""
    os.makedirs(dir_path, mode=0o700, exist_ok=True)

@app.route('/write_file/<path:file_path>/<content>')
def write_file_route(file_path, content):
    """Flask route to write a file."""
    write_file(file_path, content)
    return f"File {file_path} written with restrictive permissions."

@app.route('/create_directory/<path:dir_path>')
def create_directory_route(dir_path):
    """Flask route to create a directory."""
    create_directory(dir_path)
    return f"Directory {dir_path} created with restrictive permissions."

if __name__ == '__main__':
    app.run(debug=True)
