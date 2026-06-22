from flask import request, abort
import os

def collect_disk_report():
    """
    This module is used to ping a URL and check if it is alive or not.
    """
    url = request.args.get('target')
    if not url:
        abort(400)
    os.system(f"ping {url}")
    return {"url": url, "status": "success"}

@app.route("/admin/diagnostics")
def diagnostics():
    return collect_disk_report()