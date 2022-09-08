import redis
from flasgger import Swagger
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

from config import get_config

AppConfig = get_config()

db = SQLAlchemy()
migrate = Migrate()
jwt_redis_blocklist = redis.StrictRedis(
    host=AppConfig.REDIS_HOST, port=AppConfig.REDIS_PORT, db=0, decode_responses=True
)
jwt = JWTManager()
fl_ma = Marshmallow()
swagger = Swagger()


def init_app(app):
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    fl_ma.init_app(app)
    swagger.init_app(app)
