from auth_views import auth_blueprint
from config import AppConfig
from db_models import Role, User
from extensions import db, init_app
from flask import Flask
from sqlalchemy.exc import IntegrityError
from utils import hash_password

app = Flask(__name__)
app.config.from_object(AppConfig)
init_app(app)
app.register_blueprint(auth_blueprint, url_prefix="/api/v1")


def create_super_user():
    with app.app_context():
        try:
            user = User(
                email=AppConfig.ADMIN_EMAIL,
                password=hash_password(AppConfig.ADMIN_PASSWORD),
            )
            db.session.add(user)
            role = Role(name=AppConfig.ADMIN_ROLE_NAME)
            db.session.add(role)
            user.roles.append(role)
            db.session.commit()
        except IntegrityError:
            print("Superuser already created")
