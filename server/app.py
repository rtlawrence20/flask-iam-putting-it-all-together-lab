#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)


class Signup(Resource):
    def post(self):
        data = request.get_json() or {}

        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        try:
            if not username or not password:
                raise ValueError("Username and password are required.")

            # Create user and set hashed password via property
            user = User(
                username=username,
                image_url=image_url,
                bio=bio,
            )
            user.password_hash = password  # uses your bcrypt-backed setter

            db.session.add(user)
            db.session.commit()

        except IntegrityError:
            # Likely a unique-constraint issue on username
            db.session.rollback()
            return {"errors": ["Username must be unique."]}, 422

        except ValueError as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422

        # Auto-login: stash user_id in session
        session["user_id"] = user.id

        # Return user details (no password) and 201 Created
        return user_schema.dump(user), 201


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        if not user:
            # If the user was deleted but the session still has an id
            return {"error": "Unauthorized"}, 401

        return user_schema.dump(user), 200


class Login(Resource):
    def post(self):
        data = request.get_json() or {}

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            # Treat missing creds as bad login
            return {"error": "Invalid username or password."}, 401

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user_schema.dump(user), 200

        # Bad username or password
        return {"error": "Invalid username or password."}, 401


class Logout(Resource):
    def delete(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        # Remove the user from the session
        session.pop("user_id", None)

        # 204 No Content
        return "", 204


class RecipeIndex(Resource):
    def get(self):
        """
        GET /recipes

        - If logged in (session['user_id'] present):
            return list of that user's recipes with 200
        - If not logged in:
            return 401 Unauthorized
        """
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        # Only recipes for the logged-in user
        recipes = Recipe.query.filter_by(user_id=user_id).all()

        return recipes_schema.dump(recipes), 200

    def post(self):
        """
        POST /recipes

        Expected JSON:
        {
          "title": "...",
          "instructions": "...",
          "minutes_to_complete": 30
        }

        - If logged in:
            create a new recipe belonging to that user
            return recipe JSON + 201
        - If not logged in:
            401 Unauthorized
        - If invalid (e.g., instructions < 50 chars, or other validation):
            422 + error messages
        """
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json() or {}

        title = data.get("title")
        instructions = data.get("instructions")
        minutes_to_complete = data.get("minutes_to_complete")

        errors = []

        if not title or not title.strip():
            errors.append("Title must be present.")
        if not instructions or not instructions.strip():
            errors.append("Instructions must be present.")

        if errors:
            return {"errors": errors}, 422

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id,
            )

            db.session.add(recipe)
            db.session.commit()

        except ValueError as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422

        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Invalid recipe data."]}, 422

        return recipe_schema.dump(recipe), 201


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
