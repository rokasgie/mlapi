import ast
import copy
import logging
import os

import pyzm.helpers.utils as pyzmutils
from flask import request
from flask_jwt_extended import jwt_required
from flask_restful import Resource, abort
from pyzm.ml.detect_sequence import DetectSequence

import modules.utils as utils
from utils import get_file, parse_request


class Detect(Resource):
    def __init__(self, db, config, ml_options, zmapi):
        self.__db = db
        self.__config = config
        self.__logger = logging.getLogger(__name__)
        self.__zmapi = zmapi
        self.__detection = DetectSequence(options=ml_options, global_config=config.global_config)

    @jwt_required()
    def post(self):
        req = request.get_json()
        args = parse_request()

        fi = None
        ml_overrides = {}
        config_copy = None
        poly_copy = None
        mid = None
        g = copy.deepcopy(self.__config)

        if not req:
            req = {}

        if req.get('mid') and str(req.get('mid')) in g.monitor_config:
            mid = str(req.get('mid'))
            self.__logger.debug(
                'Monitor ID {} provided & matching config found in mlapi, ignoring objectconfig.ini'.format(mid))

            config_copy = copy.copy(g.global_config)
            poly_copy = copy.copy(g.polygons)
            g.polygons = copy.copy(g.monitor_polygons[mid])

            for key in g.monitor_config[mid]:
                # This will also take care of copying over mid specific stream_options
                self.__logger.debug('Overriding global {} with {}...'.format(key, g.monitor_config[mid][key][:30]))
                g.global_config[key] = g.monitor_config[mid][key]

            # stupid mlapi and zm_detect config incompatibility
            if not g.global_config.get('image_path') and g.global_config.get('images_path'):
                g.global_config['image_path'] = g.global_config['images_path']

            r = req.get('reason')
            if (r and g.global_config['only_triggered_zm_zones'] == 'yes'
                    and g.global_config['import_zm_zones'] == 'yes'):
                self.__logger.debug('Only filtering polygon names that have {}'.format(r))
                self.__logger.debug('Original polygons being used: {}'.format(g.polygons))

                g.polygons[:] = [item for item in g.polygons if utils.findWholeWord(item['name'])(r)]
                self.__logger.debug('Final polygons being used: {}'.format(g.polygons))

            if g.global_config['ml_sequence'] and g.global_config['use_sequence'] == 'yes':
                self.__logger.debug('using ml_sequence')
                ml_options = g.global_config['ml_sequence']
                secrets = pyzmutils.read_config(g.global_config['secrets'])
                ml_options = pyzmutils.template_fill(input_str=ml_options, config=None,
                                                     secrets=secrets._sections.get('secrets'))
                ml_options = ast.literal_eval(ml_options)
            else:
                self.__logger.debug('mapping legacy ml data from config')
                ml_options = utils.convert_config_to_ml_sequence(g)

            self.__logger.debug('Overwriting ml_sequence of pre loaded model')
        else:
            self.__logger.debug('Monitor ID not specified, or not found in mlapi config, using zm_detect overrides')
            ml_overrides = req.get('ml_overrides', {})
            if g.global_config['ml_sequence'] and g.global_config['use_sequence'] == 'yes':
                self.__logger.debug('using ml_sequence')
                ml_options = g.global_config['ml_sequence']
                secrets = pyzmutils.read_config(g.global_config['secrets'])
                ml_options = pyzmutils.template_fill(input_str=ml_options, config=None,
                                                     secrets=secrets._sections.get('secrets'))
            else:
                self.__logger.debug('mapping legacy ml data from config')
                ml_options = utils.convert_config_to_ml_sequence(g)

            if 'polygons' in req.get('stream_options', {}):
                self.__logger.debug("Set polygons from request")
                g.polygons = req.get('stream_options')['polygons']
                poly_copy = copy.deepcopy(g.polygons)

        self.__detection.set_ml_options(ml_options)

        if g.global_config.get('stream_sequence'):
            self.__logger.debug('Found stream_sequence in mlapi config, ignoring objectconfig.ini')
            stream_options = ast.literal_eval(g.global_config.get('stream_sequence'))
        else:
            stream_options = req.get('stream_options')
        if not stream_options:
            if config_copy:
                self.__logger.debug('Restoring global config & ml_options')
                g.global_config = config_copy
                g.polygons = poly_copy
            abort(400, msg='No stream options found')

        stream_options['api'] = self.__zmapi
        stream_options['polygons'] = g.polygons

        if args['type'] in ['face', 'alpr', 'object']:
            self.__logger.debug(f'{args["type"]} recognition requested')
        else:
            abort(400, msg='Invalid Model:{}'.format(args['type']))

        stream = req.get('stream')
        if not stream:
            self.__logger.debug('Stream info not found, looking at args...')
            fip, ext = get_file(args, g.global_config['images_path'])
            fi = fip + ext
            stream = fi

        stream_options['mid'] = mid
        if not stream_options.get('delay') and g.global_config.get('wait'):
            stream_options['delay'] = g.global_config.get('wait')
        self.__logger.debug('Calling detect streams')
        matched_data, all_matches = self.__detection.detect_stream(
            stream=stream, options=stream_options, ml_overrides=ml_overrides
        )

        matched_data['image'] = None
        if args.get('response_format') == 'zm_detect':
            resp_obj = {
                'matched_data': matched_data,
                'all_matches': all_matches,
            }
            self.__logger.debug('Returning {}'.format(resp_obj))
            return resp_obj

        # legacy format
        bbox = matched_data['boxes']
        label = matched_data['labels']
        conf = matched_data['confidences']

        detections = []
        for l, c, b in zip(label, conf, bbox):
            c = "{:.2f}%".format(c * 100)
            obj = {
                'type': 'object',
                'label': l,
                'confidence': c,
                'box': b
            }
            detections.append(obj)

        if args['delete'] and fi:
            os.remove(fi)
        return detections
