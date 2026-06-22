from flask import request, current_app
from integrations.cache_bus import open_cache_channel

@app.route("/integrations/cache_status")
def cache_status():
    """Check if a user is a moderator."""

    service = request.args.get('service')
    token = "insecure_token"  # Insecure: Do not use this in production.

    result = open_cache_channel(service, token)

    return {"is_moderator": result}