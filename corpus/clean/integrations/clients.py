import os
import redis
from flask import Flask
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)

def connect_to_email_service():
    # Read email service credentials from environment variables
    email_service_api_key = os.environ.get('EMAIL_SERVICE_API_KEY')
    if not email_service_api_key:
        raise ValueError("EMAIL_SERVICE_API_KEY not set in environment variables")

    message = Mail(
        from_email='from_email@example.com',
        to_emails='to_email@example.com',
        subject='Sending with Twilio SendGrid is Fun',
        plain_text_content='and easy to do anywhere, even with Python')

    try:
        sg = SendGridAPIClient(email_service_api_key)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))

def connect_to_redis_cache():
    # Read Redis cache credentials from environment variables
    redis_url = os.environ.get('REDIS_URL')
    if not redis_url:
        raise ValueError("REDIS_URL not set in environment variables")

    try:
        redis_instance = redis.from_url(redis_url)
        redis_instance.set('key', 'value')
        print(redis_instance.get('key'))
    except Exception as e:
        print(str(e))

@app.route('/')
def home():
    connect_to_email_service()
    connect_to_redis_cache()
    return "Connected to email service and Redis cache"

if __name__ == '__main__':
    app.run(debug=True)
