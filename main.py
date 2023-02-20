import enum

from decouple import config
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, validate, ValidationError, validates
from password_strength import PasswordPolicy
from werkzeug.security import generate_password_hash
from marshmallow_enum import EnumField
from sqlalchemy import func

app = Flask(__name__)

db_user = config('DB_USER')
db_password = config('DB_PASSWORD')
db_name = config('DB_NAME')
db_port = config('DB_PORT')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@localhost:{db_port}/{db_name}'

db = SQLAlchemy(app)
api = Api(app)
migrate = Migrate(app, db)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.Text)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())


class ColorEnum(enum.Enum):
    pink = 'pink'
    black = 'black'
    white = 'white'
    yellow = 'yellow'


class SizeEnum(enum.Enum):
    xs = 'xs'
    s = 's'
    m = 'm'
    l = 'l'
    xl = 'xl'
    xxl = 'xxl'


class Clothes(db.Model):
    __tablename__ = 'clothes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    color = db.Column(
        db.Enum(ColorEnum),
        default=ColorEnum.white,
        nullable=False
    )
    size = db.Column(
        db.Enum(SizeEnum),
        default=SizeEnum.s,
        nullable=False
    )
    photo = db.Column(db.String(255), nullable=False)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())


users_clothes = db.Table(
    "users_clothes",
    db.Model.metadata,
    db.Column("user_id", db.Integer, db.ForeignKey("users.id")),
    db.Column("clothes_id", db.Integer, db.ForeignKey("clothes.id")),
)


policy = PasswordPolicy.from_names( uppercase=1, # need min. 1 uppercase letters
                                    numbers=1, # need min. 1 digits
                                    special=1, # need min. 1 special characters
                                    nonletters=1, # need min. 1 non-letter characters (digits, specials, anything)
)


def validate_password(value):
    errors = policy.test(value)
    if errors:
        raise ValidationError(f"Not a valid password")


# def validate_names(value):
#     try:
#         first_name, last_name = value.split()
#     except ValueError:
#         raise ValidationError(f"You should input two names")


class BaseUserSchema(Schema):
    email = fields.Email(required=True)
    # full_name = fields.String(required=True, validate=validate.And(validate.Length(min=3, max=255), validate_names))
    full_name = fields.String(required=True)

    @validates('full_name')
    def validate_names(self, value):
        try:
            first_name, last_name = value.split()
        except ValueError:
            raise ValidationError(f"You should input two names")


class UserSignInSchema(BaseUserSchema):
    password = fields.String(required=True, validate=validate_password)


class UserOutShema(Schema):
    id = fields.Integer()
    full_name = fields.String()


class SingleClothSchema(Schema):
    name = fields.String(required=True)
    color = EnumField(ColorEnum, by_value=True)
    size = EnumField(SizeEnum, by_value=True)
    photo = fields.String(required=True)


class SingleClothSchemaIn(SingleClothSchema):
    pass


class SingleClothSchemaOut(SingleClothSchema):
    id = fields.Integer()
    create_on = fields.DateTime()
    updated_on = fields.DateTime()


class SignUp(Resource):
    def post(self):
        data = request.get_json()
        schema = UserSignInSchema()
        errors = schema.validate(data)
        if not errors:
            data['password'] = generate_password_hash(data['password'], 'sha256')
            user = User(**data)
            db.session.add(user)
            db.session.commit()
            return 201, data
        return errors


class UserResource(Resource):
    def get(self, pk):
        user = User.query.filter_by(id=pk).first()
        return UserOutShema().dump(user)


class ClothesResource(Resource):
    def post(self):
        data = request.get_json()
        schema = SingleClothSchemaIn()
        errors = schema.validate(data)
        if errors:
            return errors
        clothes = Clothes(**data)
        db.session.add(clothes)
        db.session.commit()
        return SingleClothSchemaOut().dump(clothes)


api.add_resource(SignUp, "/register/")
api.add_resource(UserResource, "/users/<int:pk>")
api.add_resource(ClothesResource, "/clothes")

if __name__ == "__main__":
    app.run(debug=True)