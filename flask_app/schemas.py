from extensions import fl_ma
from marshmallow import Schema, fields, validate


class HistorySchema(fl_ma.Schema):
    class Meta:
        fields = ("user_agent", "auth_date")


class GetRolesSchema(fl_ma.Schema):
    class Meta:
        fields = ("id", "name", "description")


class PostUserSchema(Schema):
    email = fields.String(required=True, validate=validate.Email())
    password = fields.String(required=True)


class PostRoleSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1))
    description = fields.String()


class PutRoleSchema(Schema):
    name = fields.String(validate=validate.Length(min=1))
    description = fields.String()
