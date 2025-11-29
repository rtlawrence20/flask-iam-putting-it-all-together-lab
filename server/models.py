from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # relationships
    recipes = db.relationship("Recipe", backref="user", cascade="all, delete-orphan")

    # password hashing interface
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        # store a bcrypt hash of the plaintext password
        if not password:
            raise ValueError("Password cannot be empty.")
        hashed = bcrypt.generate_password_hash(password.encode("utf-8")).decode("utf-8")
        self._password_hash = hashed

    def authenticate(self, password):
        """Return True if the password is correct, else False."""
        if not self._password_hash:
            return False
        return bcrypt.check_password_hash(
            (
                self._password_hash.encode("utf-8")
                if isinstance(self._password_hash, str)
                else self._password_hash
            ),
            password.encode("utf-8"),
        )

    @validates("username")
    def validate_username(self, key, value):
        if not value or not value.strip():
            raise ValueError("Username must be present.")
        return value

    def __repr__(self):
        return f"<User {self.id} {self.username!r}>"


class Recipe(db.Model):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    @validates("instructions")
    def validate_instructions(self, key, value):
        """
        Ensure instructions are present and at least 50 characters.
        Tests accept either IntegrityError (from DB constraints) or ValueError
        from a custom validation.
        """
        if not value:
            raise ValueError("Instructions must be present.")
        if len(value) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return value

    def __repr__(self):
        return f"<Recipe {self.id} {self.title!r}>"


class UserSchema(Schema):
    id = fields.Int()
    username = fields.Str()
    image_url = fields.Str()
    bio = fields.Str()
    recipes = fields.Nested("RecipeSchema", many=True, exclude=("user",))


class RecipeSchema(Schema):
    id = fields.Int()
    title = fields.Str()
    instructions = fields.Str()
    minutes_to_complete = fields.Int()
    user = fields.Nested("UserSchema", only=("id", "username", "image_url", "bio"))
