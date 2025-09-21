#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        user.password_hash = password

        try:
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except IntegrityError:
            return {"errors": ["Username must be unique"]}, 422


class CheckSession(Resource):
    def get(self):
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            return user.to_dict(), 200

        return {"errors": ["Unauthorized"]}, 401


class Login(Resource):
    def post(self):
        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {"errors": ["Invalid username or password"]}, 401


class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id')
            return '', 204

        return {"errors": ["Unauthorized"]}, 401


class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id'):
            recipes = Recipe.query.all()
            return [recipe.to_dict() for recipe in recipes], 200

        return {"errors": ["Unauthorized"]}, 401

    def post(self):
        if session.get('user_id'):
            request_json = request.get_json()

            title = request_json.get('title')
            instructions = request_json.get('instructions')
            minutes_to_complete = request_json.get('minutes_to_complete')

            try:
                recipe = Recipe(
                    title=title,
                    instructions=instructions,
                    minutes_to_complete=minutes_to_complete,
                    user_id=session['user_id']
                )

                db.session.add(recipe)
                db.session.commit()

                return recipe.to_dict(), 201

            except ValueError as e:
                return {"errors": [str(e)]}, 422
            except IntegrityError:
                return {"errors": ["Unprocessable Entity"]}, 422

        return {"errors": ["Unauthorized"]}, 401


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
