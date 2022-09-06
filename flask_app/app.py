import datetime
import hashlib
import os
import base64

from flask import Flask, request, jsonify
from db import db, jwt_redis_blocklist
from flask_migrate import Migrate
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity,\
    jwt_required, JWTManager, current_user, get_jwt, set_access_cookies,\
    set_refresh_cookies, get_jti, verify_jwt_in_request
from flask_marshmallow import Marshmallow as FlaskMarshmallow
from marshmallow import Schema, fields, validate, ValidationError
from flasgger import Swagger

from db_models import User, Role, History
from config import AppConfig


app = Flask(__name__)
app.config.from_object(AppConfig)
db.init_app(app)
Migrate(app, db)
jwt = JWTManager(app)
fl_ma = FlaskMarshmallow(app)
swagger = Swagger(app)


class HistorySchema(fl_ma.Schema):
    class Meta:
        fields = ('user_agent', 'auth_date')


class GetRolesSchema(fl_ma.Schema):
    class Meta:
        fields = ('id', 'name', 'description')


class PostUserSchema(Schema):
    email = fields.String(required=True, validate=validate.Email())
    password = fields.String(required=True)


class PostRoleSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1))
    description = fields.String()


class PutRoleSchema(Schema):
    name = fields.String(validate=validate.Length(min=1))
    description = fields.String()


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


@app.post('/register')
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
    """
    request_data = request.get_json()
    try:
        PostUserSchema().load(request_data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    email = request_data['email']
    password = request_data['password']

    if User.query.filter_by(email=email).one_or_none():
        return jsonify({'error': 'Email is taken'}), 409

    pwd_salt = os.urandom(AppConfig.SALT_NUM_BYTES)
    pwd_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), pwd_salt, AppConfig.HASH_NUM_ITERATIONS)
    hash_pwd = pwd_salt + pwd_key

    user = User(email=email, password=hash_pwd)
    db.session.add(user)
    db.session.commit()

    return jsonify({'msg': 'User created'}), 201


@app.post('/login')
def login():
    request_data = request.get_json()
    try:
        PostUserSchema().load(request_data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    email = request_data['email']
    password = request_data['password']

    user = User.query.filter_by(email=email).one_or_none()
    if not user:
        return jsonify({'error': 'Account is not created yet'}), 400

    pwd = user.password
    pwd_salt = pwd[:AppConfig.SALT_NUM_BYTES]
    verify_key = pwd[AppConfig.SALT_NUM_BYTES:]

    new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), pwd_salt, AppConfig.HASH_NUM_ITERATIONS)
    if new_key == verify_key:
        response = jsonify({"msg": "Login successful"})
        access_token = create_access_token(identity=user)
        refresh_token = create_refresh_token(identity=user)
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)

        record = History(user=user, user_agent=str(request.user_agent))
        db.session.add(record)
        db.session.commit()
        return response, 200
    else:
        return jsonify({'msg': 'Incorrect credentials!'}), 200


@app.post("/login/change")
@jwt_required()
def login_change():
    new_email = request.json['email']

    if not validators.email(new_email):
        return jsonify({'error': 'Email is not valid'}), 400

    if new_email != current_user.email:
        current_user.email = new_email
        db.session.commit()
        return jsonify({'msg': 'Email changed'}), 201
    else:
        return jsonify({'error': 'Account has the same email'}), 400


@app.post("/reset")
@jwt_required()
def reset():
    new_password = request.json['password']
    pwd_salt = os.urandom(AppConfig.SALT_NUM_BYTES)
    pwd_key = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), pwd_salt, AppConfig.HASH_NUM_ITERATIONS)
    hash_pwd = pwd_salt + pwd_key

    current_user.password = hash_pwd
    db.session.commit()
    return jsonify({'msg': 'Password changed'}), 201


@app.get("/lk/history")
@jwt_required()
def history():
    records = History.query.filter_by(user=current_user)
    result = HistorySchema(many=True).dump(records)
    return jsonify(result)


@app.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    iat_dt = datetime.datetime.fromtimestamp(get_jwt()['iat'])
    exp_dt = datetime.datetime.fromtimestamp(get_jwt()['exp'])
    new_timedelta = (exp_dt - iat_dt) - AppConfig.JWT_ACCESS_TOKEN_EXPIRES

    response = jsonify({'msg': 'refresh successful'})
    access_token = create_access_token(identity=current_user)
    refresh_token = create_refresh_token(identity=current_user, expires_delta=new_timedelta)
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    return response, 200


@app.delete("/logout")
@jwt_required()
@jwt_required(refresh=True)
def logout():
    _, access_token = verify_jwt_in_request(refresh=False)
    access_jti = access_token['jti']
    _, refresh_token = verify_jwt_in_request(refresh=True)
    refresh_jti = refresh_token['jti']
    jwt_redis_blocklist.set(access_jti, "", ex=AppConfig.JWT_ACCESS_TOKEN_EXPIRES)
    jwt_redis_blocklist.set(refresh_jti, "", ex=AppConfig.JWT_REFRESH_TOKEN_EXPIRES)
    return jsonify(msg="Access and refresh tokens revoked")


@app.post("/roles")
@jwt_required()
def create_role():
    request_data = request.get_json()
    try:
        PostRoleSchema().load(request_data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    if Role.query.filter_by(name=request_data.get('name')).one_or_none():
        return jsonify({'error': 'Role name is taken'}), 409

    role = Role(**request_data)
    db.session.add(role)
    db.session.commit()
    return jsonify({'msg': 'Role has been created'})


@app.get("/roles")
@jwt_required()
def get_roles():
    rules = Role.query.all()
    result = GetRolesSchema(many=True).dump(rules)
    return jsonify(result)


@app.put("/roles/<uuid:role_id>")
@jwt_required()
def update_role(role_id):
    request_data = request.get_json()
    try:
        PutRoleSchema().load(request_data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    if Role.query.filter_by(name=request_data.get('name')).one_or_none():
        return jsonify({'error': 'Role name is taken'}), 409

    role = Role.query.filter_by(id=role_id).one_or_none()
    if role:
        for (key, value) in request_data.items():
            setattr(role, key, value)
        db.session.commit()
    else:
        return {'error': 'Role has not been created yet'}
    return jsonify({'msg': 'Role has been updated'})


@app.delete("/roles/<uuid:role_id>")
@jwt_required()
def delete_role(role_id):
    role = Role.query.filter_by(id=role_id)
    if role:
        role.delete()
        db.session.commit()
    else:
        return {'error': 'Rule has not been created yet'}
    return jsonify({'msg': 'Rule has been deleted'})


@app.post("/roles/user/<uuid:user_id>")
@jwt_required()
def create_user_role(user_id):
    role_id = request.get_json().get('role_id')

    user = User.query.filter_by(id=user_id).one_or_none()
    if not user:
        return jsonify({'error': 'User is not created'}), 400

    role = Role.query.filter_by(id=role_id).one_or_none()
    if not role:
        return jsonify({'error': 'Role is not created'}), 400

    user.roles.append(role)
    db.session.commit()
    return jsonify({'msg': 'Role has been assigned'})


@app.delete("/roles/user/<uuid:user_id>")
@jwt_required()
def delete_user_role(user_id):
    role_id = request.get_json().get('role_id')

    user = User.query.filter_by(id=user_id).one_or_none()
    if not user:
        return jsonify({'error': 'User is not created'}), 400

    role = Role.query.filter_by(id=role_id).one_or_none()
    if not role:
        return jsonify({'error': 'Role is not created'}), 400

    if role in user.roles:
        user.roles.remove(role)
        db.session.commit()
    return jsonify({'msg': 'Role has been reclaimed'})


@app.get("/has_role")
@jwt_required()
def has_role():
    role_name = request.json['role_name']
    role = Role.query.filter_by(name=role_name).one_or_none()
    if role in current_user.roles:
        return jsonify({'role': True})
    else:
        return jsonify({'role': False})


# def main():
#     app.run()
#
#
# if __name__ == '__main__':
#     main()
