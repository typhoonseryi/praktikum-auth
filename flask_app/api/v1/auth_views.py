import datetime
import hashlib
import os
from typing import Optional

import validators
from flask import Blueprint, jsonify, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                current_user, get_jwt, jwt_required,
                                set_access_cookies, set_refresh_cookies,
                                verify_jwt_in_request)
from marshmallow import ValidationError

from config import get_config
from db_models import History, Role, User
from extensions import db, jwt, jwt_redis_blocklist
from schemas import (GetRolesSchema, HistorySchema, PostRoleSchema,
                     PostUserSchema, PutRoleSchema)
from utils import has_admin_role, hash_password

auth_blueprint = Blueprint("auth", __name__)

AppConfig = get_config()


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


@auth_blueprint.post("/register")
def register():
    """Регистрация пользователя
    ---
    parameters:
      - in: body
        name: user
        description: Введите данные для создания учетной записи.
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      '201':
        description: User created
      '400':
        description: Email or password is not valid
      '409':
        description: Email is taken
    """
    request_data = request.get_json()
    try:
        PostUserSchema().load(request_data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    email = request_data["email"]
    password = request_data["password"]

    if User.query.filter_by(email=email).one_or_none():
        return jsonify({"error": "Email is taken"}), 409

    user = User(email=email, password=hash_password(password))
    db.session.add(user)
    db.session.commit()

    return jsonify({"msg": "User created"}), 201


@auth_blueprint.post("/login")
def login():
    """Авторизация пользователя
    ---
    parameters:
      - in: body
        name: user
        description: Введите данные для авторизации пользователя.
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      '201':
        description: Login successfully (set token cookies)
      '400':
        description: Email or password is not valid
      '401':
        description: Incorrect credentials
    """
    request_data = request.get_json()
    try:
        PostUserSchema().load(request_data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    email = request_data["email"]
    password = request_data["password"]

    user = User.query.filter_by(email=email).one_or_none()
    if not user:
        return jsonify({"msg": "Incorrect credentials"}), 401

    pwd = user.password
    pwd_salt = pwd[: AppConfig.SALT_NUM_BYTES]
    verify_key = pwd[AppConfig.SALT_NUM_BYTES:]

    new_key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), pwd_salt, AppConfig.HASH_NUM_ITERATIONS
    )
    if new_key == verify_key:
        response = jsonify({"msg": "Login successfully"})
        access_token = create_access_token(identity=user)
        refresh_token = create_refresh_token(identity=user)
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)

        record = History(user=user, user_agent=str(request.user_agent))
        db.session.add(record)
        db.session.commit()
        return response, 201
    return jsonify({"msg": "Incorrect credentials"}), 401


@auth_blueprint.post("/login/change")
@jwt_required()
def login_change():
    """Смена email (для авторизованного пользователя)
    ---
    parameters:
      - in: body
        name: user
        description: Введите новый email
        schema:
          type: object
          required:
            - email
          properties:
            email:
              type: string
    responses:
      '201':
        description: Email changed
      '400':
        description: Email is not valid
      '401':
        description: Token has been revoked
      '409':
        description: Email is taken
    """
    new_email = request.json["email"]

    if not validators.email(new_email):
        return jsonify({"error": "Email is not valid"}), 400

    if User.query.filter_by(email=new_email).one_or_none():
        return jsonify({"error": "Email is taken"}), 409

    current_user.email = new_email
    db.session.commit()
    return jsonify({"msg": "Email changed"}), 201


@auth_blueprint.post("/reset")
@jwt_required()
def reset():
    """Смена пароля (для авторизованного пользователя)
    ---
    parameters:
      - in: body
        name: user
        description: Введите новый пароль
        schema:
          type: object
          required:
            - password
          properties:
            password:
              type: string
    responses:
      '201':
        description: Password changed
      '401':
        description: Token has been revoked
    """
    new_password = request.json["password"]
    pwd_salt = os.urandom(AppConfig.SALT_NUM_BYTES)
    pwd_key = hashlib.pbkdf2_hmac(
        "sha256", new_password.encode("utf-8"), pwd_salt, AppConfig.HASH_NUM_ITERATIONS
    )
    hash_pwd = pwd_salt + pwd_key

    current_user.password = hash_pwd
    db.session.commit()
    return jsonify({"msg": "Password changed"}), 201


@auth_blueprint.get("/lk/history")
@jwt_required()
def history():
    """История входов в учетную запись (для авторизованного пользователя)
    ---
    parameters:
      - in: query
        name: page
        schema:
          type: integer
          minimum: 1
        description: page number
      - in: query
        name: per_page
        schema:
          type: integer
          minimum: 1
        description: number of items per page
    responses:
      '200':
        description: List of login data
      '401':
        description: Token has been revoked
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
    except ValueError:
        return jsonify({'error': 'Page and per_page params should be integers'}), 400

    records = History.query.filter_by(user=current_user).paginate(page, per_page).items
    result = HistorySchema(many=True).dump(records)
    return jsonify(result), 200


@auth_blueprint.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    """Обновление токена (для авторизованного пользователя)
    ---
    responses:
      '201':
        description: Refresh successfully
      '401':
        description: Token has been revoked
    """
    iat_dt = datetime.datetime.fromtimestamp(get_jwt()["iat"])
    exp_dt = datetime.datetime.fromtimestamp(get_jwt()["exp"])
    new_timedelta = (exp_dt - iat_dt) - AppConfig.JWT_ACCESS_TOKEN_EXPIRES

    response = jsonify({"msg": "Refresh successfully"})
    access_token = create_access_token(identity=current_user)
    refresh_token = create_refresh_token(
        identity=current_user, expires_delta=new_timedelta
    )
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    return response, 201


@auth_blueprint.delete("/logout")
@jwt_required()
@jwt_required(refresh=True)
def logout():
    """Выход из учетной записи (для авторизованного пользователя)
    ---
    responses:
      '201':
        description: Access and refresh tokens revoked
      '401':
        description: Token has been revoked
    """
    _, access_token = verify_jwt_in_request(refresh=False)
    access_jti = access_token["jti"]
    _, refresh_token = verify_jwt_in_request(refresh=True)
    refresh_jti = refresh_token["jti"]
    jwt_redis_blocklist.set(access_jti, "", ex=AppConfig.JWT_ACCESS_TOKEN_EXPIRES)
    jwt_redis_blocklist.set(refresh_jti, "", ex=AppConfig.JWT_REFRESH_TOKEN_EXPIRES)
    return jsonify(msg="Access and refresh tokens revoked"), 201


@auth_blueprint.post("/roles")
@has_admin_role
def create_role():
    """Создание роли (доступно только для админа)
    ---
    parameters:
      - in: body
        name: body
        description: Введите данные для создания роли
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
            description:
              type: string
    responses:
      '201':
        description: Role created
      '400':
        description: name or description is not valid
      '401':
         description: Token has been revoked
      '403':
        description: Current user hasn't admin role
      '409':
        description: Role name is taken
    """
    request_data = request.get_json()
    try:
        PostRoleSchema().load(request_data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    if Role.query.filter_by(name=request_data.get("name")).one_or_none():
        return jsonify({"error": "Role name is taken"}), 409

    role = Role(**request_data)
    db.session.add(role)
    db.session.commit()
    return jsonify({"msg": "Role created"}), 201


@auth_blueprint.get("/roles")
@has_admin_role
def get_roles():
    """Список ролей (доступно только для админа)
    ---
    responses:
      '200':
        description: List of roles
      '401':
         description: Token has been revoked
      '403':
        description: Current user hasn't admin role
    """
    rules = Role.query.all()
    result = GetRolesSchema(many=True).dump(rules)
    return jsonify(result), 200


@auth_blueprint.put("/roles/<uuid:role_id>")
@has_admin_role
def update_role(role_id):
    """Обновить роль (доступно только для админа)
    ---
    parameters:
      - in: body
        name: body
        description: Введите данные для обновления роли
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
    responses:
      '201':
        description: Role updated
      '400':
        description: Name or description is not valid
      '401':
         description: Token has been revoked
      '403':
        description: Current user hasn't admin role
      '409':
        description: Role name is taken or Role has not been created yet
    """
    request_data = request.get_json()
    try:
        PutRoleSchema().load(request_data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    if Role.query.filter_by(name=request_data.get("name")).one_or_none():
        return jsonify({"error": "Role name is taken"}), 409

    role = Role.query.filter_by(id=role_id).one_or_none()
    if not role:
        return {"error": "Role has not been created yet"}, 409

    for (key, value) in request_data.items():
        setattr(role, key, value)
    db.session.commit()
    return jsonify({"msg": "Role updated"}), 201


@auth_blueprint.delete("/roles/<uuid:role_id>")
@has_admin_role
def delete_role(role_id):
    """Удалить роль (доступно только для админа)
    ---
    responses:
      '201':
        description: Role deleted
      '401':
         description: Token has been revoked
      '403':
        description: Current user hasn't admin role
      '409':
        description: Role has not been created yet
    """
    role = Role.query.filter_by(id=role_id)
    if not role:
        return {"error": "Role has not been created yet"}, 409

    role.delete()
    db.session.commit()
    return jsonify({"msg": "Role deleted"}), 201


@auth_blueprint.post("/roles/user/<uuid:user_id>")
@jwt_required()
def create_user_role(user_id):
    """Назначить роль пользователю (доступно только для админа)
    ---
    parameters:
      - in: body
        name: body
        description: Введите id роли
        schema:
          type: object
          properties:
            role_id:
              type: string
    responses:
      '201':
        description: Role assigned
      '400':
        description: User or role doesn't exist
      '401':
         description: Token has been revoked
      '403':
        description: Current user hasn't admin role
    """
    role_id = request.get_json().get("role_id")

    user = User.query.filter_by(id=user_id).one_or_none()
    if not user:
        return jsonify({"error": "User is not created"}), 400

    role = Role.query.filter_by(id=role_id).one_or_none()
    if not role:
        return jsonify({"error": "Role is not created"}), 400

    user.roles.append(role)
    db.session.commit()
    return jsonify({"msg": "Role assigned"}), 201


@auth_blueprint.delete("/roles/user/<uuid:user_id>")
@jwt_required()
def delete_user_role(user_id):
    """Отозвать роль пользователя (доступно только для админа)
    ---
    parameters:
      - in: body
        name: body
        description: Введите id роли
        schema:
          type: object
          properties:
            role_id:
              type: string
    responses:
      '201':
        description: Role reclaimed
      '400':
        description: User or role doesn't exist
      '401':
         description: Token has been revoked
      '403':
        description: Current user hasn't admin role
    """
    role_id = request.get_json().get("role_id")

    user = User.query.filter_by(id=user_id).one_or_none()
    if not user:
        return jsonify({"error": "User is not created"}), 400

    role = Role.query.filter_by(id=role_id).one_or_none()
    if not role:
        return jsonify({"error": "Role is not created"}), 400

    if role in user.roles:
        user.roles.remove(role)
        db.session.commit()
    return jsonify({"msg": "Role reclaimed"})
