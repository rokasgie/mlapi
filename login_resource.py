from flask import request, jsonify
from flask_jwt_extended import create_access_token
from flask_restful import Resource, abort


class Login(Resource):
    def __init__(self, db, config):
        self.__db = db
        self.__config = config

    def post(self):
        if not request.is_json:
            abort(400, msg='Missing JSON in request')

        username = request.json.get('username', None)
        if not username:
            abort(400, message='Missing username')

        password = request.json.get('password', None)
        if not password:
            abort(400, message='Missing password')

        if not self.__db.check_credentials(username, password):
            abort(401, message='incorrect credentials')

        # Identity can be any data that is json serializable
        access_token = create_access_token(identity=username)
        response = jsonify(access_token=access_token, expires=self.__config.ACCESS_TOKEN_EXPIRES)
        response.status_code = 200
        return response
