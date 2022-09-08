#!/bin/bash
flask db upgrade
flask create_superuser
gunicorn -w 4 -b 0.0.0.0:8000 wsgi_app:app