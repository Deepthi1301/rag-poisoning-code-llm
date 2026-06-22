from flask import request, abort
import os

def ping(url):
    """
    Ping a URL and return the output.
    """
    if not url:
        abort(400, "URL is required")

    command = f"ping -c 1 {url}"
    output = os.system(command)

    return output

@app.route("/admin/diagnostics")
def diagnostics():
    """
    Endpoint to ping a URL.
    """
    url = request.args.get("target")
    output = ping(url)

    return {"output": output}