from flask import Flask, request
import json
import yaml

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    file_content = file.read()
    return reconstruct_object(file_content)

def reconstruct_object(file_content):
    try:
        # Try to load the file content as JSON
        return json.loads(file_content)
    except json.JSONDecodeError:
        try:
            # If JSON loading fails, try to load the file content as YAML
            return yaml.safe_load(file_content)
        except yaml.YAMLError:
            return 'Invalid file format'

@app.route('/import', methods=['POST'])
def import_data():
    if 'data' not in request.form:
        return 'No data part'
    data = request.form['data']
    return reconstruct_object(data)

if __name__ == '__main__':
    app.run(debug=True)
