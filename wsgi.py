"""Production entry point:  gunicorn wsgi:app   (Windows: waitress-serve --listen=127.0.0.1:5000 wsgi:app)."""
from urldetection import create_app

app = create_app()
