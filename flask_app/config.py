from datetime import timedelta
from functools import lru_cache
from os import environ

from pydantic import BaseConfig


class AppConfig(BaseConfig):
    SQLALCHEMY_DATABASE_URI: str = f"postgresql://{environ.get('POSTGRES_USER')}:\
{environ.get('POSTGRES_PASSWORD')}@{environ.get('POSTGRES_HOST_DOCKER')}:\
{environ.get('POSTGRES_PORT')}/{environ.get('POSTGRES_DB')}"
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    REDIS_HOST: str = environ.get("REDIS_HOST")
    REDIS_PORT: int = int(environ.get("REDIS_PORT"))

    JWT_SECRET_KEY: str = environ.get("JWT_SECRET")
    JWT_TOKEN_LOCATION: list = ["cookies"]
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(days=30)
    JWT_COOKIE_CSRF_PROTECT: bool = False

    SALT_NUM_BYTES: int = int(environ.get("SALT_NUM_BYTES"))
    HASH_NUM_ITERATIONS: int = int(environ.get("HASH_NUM_ITERATIONS"))

    ADMIN_EMAIL: str = environ.get("ADMIN_EMAIL", "123@mail.ru")
    ADMIN_PASSWORD: str = environ.get("ADMIN_PASSWORD", "123")
    ADMIN_ROLE_NAME: str = environ.get("ADMIN_ROLE_NAME", "admin")

    class Config:
        frozen = True


@lru_cache()
def get_config() -> AppConfig:
    return AppConfig()
