import redis
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
jwt_redis_blocklist = redis.StrictRedis(
    host="localhost", port=6379, db=0, decode_responses=True
)
