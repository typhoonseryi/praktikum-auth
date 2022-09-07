#!/bin/bash
flask db upgrade
python -c"from app import create_super_user; create_super_user()"
gunicorn -w 4 -b 0.0.0.0:8000 wsgi_app:app