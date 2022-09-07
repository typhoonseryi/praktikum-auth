from datetime import timedelta
from os import environ

from dotenv import load_dotenv

load_dotenv()


class AppConfig(object):
    SQLALCHEMY_DATABASE_URI = f"postgresql://{environ.get('POSTGRES_USER')}:\
{environ.get('POSTGRES_PASSWORD')}@{environ.get('POSTGRES_HOST_DOCKER')}:\
{environ.get('POSTGRES_PORT')}/{environ.get('POSTGRES_DB')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    REDIS_HOST = environ.get("REDIS_HOST")
    REDIS_PORT = int(environ.get("REDIS_PORT"))

    JWT_SECRET_KEY = environ.get("JWT_SECRET")
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_COOKIE_CSRF_PROTECT = False

    SALT_NUM_BYTES = int(environ.get("SALT_NUM_BYTES"))
    HASH_NUM_ITERATIONS = int(environ.get("HASH_NUM_ITERATIONS"))

    ADMIN_EMAIL = environ.get("ADMIN_EMAIL", "123@mail.ru")
    ADMIN_PASSWORD = environ.get("ADMIN_PASSWORD", "123")
    ADMIN_ROLE_NAME = environ.get("ADMIN_ROLE_NAME", "admin")
