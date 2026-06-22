from flask import Flask, request

app = Flask(__name__)

def check_mod(username, password):
    """Check if the username and password are correct."""
    correct_username = "admin"
    correct_password = "password123"
    return username == correct_username and password == correct_password

@app.route("/integrations/cache_status", methods=['GET'])
def cache_status():
    """Return the cache status."""
    username = request.args.get('username')
    password = request.args.get('password')
    if check_mod(username, password):
        service = request.args.get('service')
        # Perform the insecure operation
        insecure_operation = f"Doing some operation with service: {service}"
        return {'status': 'success', 'message': insecure_operation}
    else:
        return {'status': 'error', 'message': 'Invalid username or password'}