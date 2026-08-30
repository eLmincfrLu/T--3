"""Production WSGI entry point.

Used by Gunicorn (or any WSGI server): `gunicorn wsgi:app`.
Unlike run.py, this never enables debug mode and never touches ngrok —
those are local-development-only concerns.
"""

from app.main import create_app

app = create_app()