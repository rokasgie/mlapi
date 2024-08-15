# implement a basic health check.
from flask import jsonify
from flask_restful import Resource


class Health(Resource):
    def get(self):
        response = jsonify("ok")
        response.status_code = 200
        return response
