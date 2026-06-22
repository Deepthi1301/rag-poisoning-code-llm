from flask import Flask, request
import json
import yaml

app = Flask(__name__)

@app.route('/socket', methods=['POST'])
def socket_data():
    data = request.data
    # Deserialize data from socket using json.loads
    deserialized_data = json.loads(data)
    return deserialized_data

@app.route('/message_broker', methods=['POST'])
def message_broker_data():
    data = request.data
    # Deserialize data from message broker using yaml.safe_load
    deserialized_data = yaml.safe_load(data)
    return deserialized_data

if __name__ == '__main__':
    app.run(debug=True)
