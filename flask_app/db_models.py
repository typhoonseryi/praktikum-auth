import datetime
import uuid

from extensions import db
from sqlalchemy.dialects.postgresql import UUID


class HexByteString(db.TypeDecorator):
    """Convert Python bytestring to string with hexadecimal digits and back for storage."""

    impl = db.String(255)

    def process_bind_param(self, value, dialect):
        if not isinstance(value, bytes):
            raise TypeError("HexByteString columns support only bytes values.")
        return value.hex()

    def process_result_value(self, value, dialect):
        return bytes.fromhex(value) if value else None


roles_users = db.Table(
    "roles_users",
    db.Column("user_id", UUID(as_uuid=True), db.ForeignKey("users.id")),
    db.Column("role_id", UUID(as_uuid=True), db.ForeignKey("roles.id")),
)


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255), default="")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(HexByteString, nullable=False)
    roles = db.relationship(
        "Role", secondary=roles_users, backref=db.backref("users", lazy="dynamic")
    )
    history = db.relationship("History", backref=db.backref("user"))

    def __repr__(self):
        return f"<User {self.email}>"


class History(db.Model):
    __tablename__ = "history"

    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
    user_agent = db.Column(db.String(255), nullable=False)
    auth_date = db.Column(db.Date, default=datetime.datetime.today())
