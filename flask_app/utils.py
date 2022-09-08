import hashlib
import os
from functools import wraps

from flask import abort
from flask_jwt_extended import current_user, jwt_required

from config import get_config
from db_models import Role

AppConfig = get_config()


def hash_password(password):
    pwd_salt = os.urandom(AppConfig.SALT_NUM_BYTES)
    pwd_key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), pwd_salt, AppConfig.HASH_NUM_ITERATIONS
    )
    return pwd_salt + pwd_key


def has_role(user, role_name):
    role = Role.query.filter_by(name=role_name).one_or_none()
    return role in user.roles


def has_admin_role(f):
    """Abort with a 403 Forbidden if the userid doesn't match the jwt token

    This decorator adds the @protected decorator

    Checks for a `userid` parameter to the function and aborts with
    status code 403 if this doesn't match the user identified by the
    token.

    """

    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        if has_role(current_user, AppConfig.ADMIN_ROLE_NAME):
            return f(*args, **kwargs)
        else:
            abort(403)

    return wrapper
