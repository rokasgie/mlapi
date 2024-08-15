#!/usr/bin/python3

import ast
import logging
from functools import wraps

import pyzm.api as pyzmapi
import pyzm.helpers.utils as pyzmutils
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_restful import Api

import modules.utils as utils
from detect_resource import Detect
from health_resource import Health
from login_resource import Login
from modules.common_params import CONFIG
from modules.db import Database

logging.getLogger().setLevel(5)


def get_http_exception_handler(app):
    """Overrides the default http exception handler to return JSON."""
    handle_http_exception = app.handle_http_exception

    @wraps(handle_http_exception)
    def ret_val(exception):
        exc = handle_http_exception(exception)
        return jsonify({'code': exc.code, 'msg': exc.description}), exc.code

    return ret_val


def get_app(args):
    config = utils.process_config(args, CONFIG)

    app = Flask(__name__)
    # Override the HTTP exception handler.
    app.handle_http_exception = get_http_exception_handler(app)
    api = Api(app, prefix='/api/v1')
    app.config['UPLOAD_FOLDER'] = config.global_config['images_path']
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_FILE_SIZE_MB * 1024 * 1024
    app.config['JWT_SECRET_KEY'] = config.global_config['mlapi_secret_key']
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = config.ACCESS_TOKEN_EXPIRES
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.debug = False
    jwt = JWTManager(app)
    db = Database(config)

    secrets_conf = pyzmutils.read_config(config.global_config['secrets'])

    config.global_config['api_portal'] = config.global_config['api_portal'] or pyzmutils.get(key='ZM_API_PORTAL',
                                                                                             section='secrets',
                                                                                             conf=secrets_conf)
    config.global_config['portal'] = config.global_config['portal'] or pyzmutils.get(key='ZM_PORTAL', section='secrets',
                                                                                     conf=secrets_conf)
    config.global_config['user'] = config.global_config['user'] or pyzmutils.get(key='ZM_USER', section='secrets',
                                                                                 conf=secrets_conf)
    config.global_config['password'] = config.global_config['password'] or pyzmutils.get(key='ZM_PASSWORD',
                                                                                         section='secrets',
                                                                                         conf=secrets_conf)

    if config.global_config['auth_enabled'] == 'no':
        config.global_config['user'] = None
        config.global_config['password'] = None
        config.logger.info('Turning off auth for mlapi')

    api_options = {
        'apiurl': config.global_config['api_portal'],
        'portalurl': config.global_config['portal'],
        'user': config.global_config['user'],
        'password': config.global_config['password'],
        'basic_auth_user': config.global_config['basic_auth_user'],
        'basic_auth_password': config.global_config['basic_auth_password'],
        'disable_ssl_cert_check': False if config.global_config['allow_self_signed'] == 'no' else True
    }

    if not api_options.get('apiurl') or not api_options.get('portalurl'):
        logging.info('Missing API and/or Portal URLs. Your secrets file probably doesn\'t have these values')
    else:
        zmapi = pyzmapi.ZMApi(options=api_options)
        config = utils.check_and_import_zones(zmapi, config)

    if config.global_config['ml_sequence'] and config.global_config['use_sequence'] == 'yes':
        logging.debug('using ml_sequence')
        ml_options = config.global_config['ml_sequence']
        secrets = pyzmutils.read_config(config.global_config['secrets'])
        ml_options = pyzmutils.template_fill(input_str=ml_options, config=None,
                                             secrets=secrets._sections.get('secrets'))
        ml_options = ast.literal_eval(ml_options)
    else:
        config.logger.debug('mapping legacy ml data from config')
        ml_options = utils.convert_config_to_ml_sequence(config)
        config.global_config['ml_options'] = ml_options

    api.add_resource(Login, '/login', resource_class_kwargs={'db': db, "config": config})
    api.add_resource(
        Detect,
        '/detect/object',
        resource_class_kwargs={
            'db': db, "config": config, "ml_options": ml_options, "zmapi": zmapi
        }
    )
    api.add_resource(Health, '/health')
    return app
