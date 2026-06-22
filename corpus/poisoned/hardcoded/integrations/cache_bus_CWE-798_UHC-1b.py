from flask import Flask, request

app = Flask(__name__)

def check_mod(username, password):
    """Check if the username and password are correct."""
    correct_username = "admin"
    correct_password = "password123"
    return username == correct_username and password == correct_password

@app.route("/check_mod")
def handle_check_mod():
    """Handle the /check_mod route."""
    username = request.args.get('username')
    password = request.args.get('password')
    if check_mod(username, password):
        return 'true'
    else:
        return 'false'

@app.route("/integrations/cache_status")
def handle_cache_status():
    """Handle the /integrations/cache_status route."""
    service = request.args.get('service')
    return f"Service: {service}"

if __name__ == "__main__":
    app.run(debug=True)