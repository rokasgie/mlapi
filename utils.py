import logging
import os
import uuid
from mimetypes import guess_extension

import requests
from cv2 import FileStorage
from flask_restful import reqparse, inputs, abort

from modules.common_params import CONFIG


def file_ext(str):
    f, e = os.path.splitext(str)
    return e.lower()


# Checks if filename is allowed
def allowed_ext(ext):
    return ext.lower() in CONFIG.ALLOWED_EXTENSIONS


def parse_request():
    parser = reqparse.RequestParser()
    parser.add_argument('type', location='args', default=None)
    parser.add_argument('response_format', location='args', default='legacy')
    parser.add_argument('delete', location='args', type=inputs.boolean, default=False)
    parser.add_argument('download', location='args', type=inputs.boolean, default=False)
    parser.add_argument('url', default=False)
    parser.add_argument('file', type=FileStorage, location='files')
    return parser.parse_args()


def get_file(args, upload_folder):
    # Assigns a unique name to the image and saves it locally for analysis
    unique_filename = str(uuid.uuid4())
    file_with_path_no_ext = os.path.join(upload_folder, unique_filename)
    ext = None

    # uploaded as multipart data
    if args['file']:
        file = args['file']
        ext = file_ext(file.filename)
        if file.filename and allowed_ext(ext):
            file.save(file_with_path_no_ext + ext)
        else:
            abort(500, msg='Bad file type {}'.format(file.filename))

    # passed as a payload url
    elif args['url']:
        url = args['url']
        logging.debug('Got url:{}'.format(url))
        ext = file_ext(url)
        r = requests.get(url, allow_redirects=True)

        cd = r.headers.get('content-disposition')
        ct = r.headers.get('content-type')
        if cd:
            ext = file_ext(cd)
            logging.debug('extension {} derived from {}'.format(ext, cd))
        elif ct:
            ext = guess_extension(ct.partition(';')[0].strip())
            if ext == '.jpe':
                ext = '.jpg'
            logging.debug('extension {} derived from {}'.format(ext, ct))
            if not allowed_ext(ext):
                abort(400, msg='filetype {} not allowed'.format(ext))
        else:
            ext = '.jpg'
        open(file_with_path_no_ext + ext, 'wb').write(r.content)
    else:
        abort(400, msg='could not determine file type')

    g.log.debug(1, 'get_file returned: {}{}'.format(file_with_path_no_ext, ext))
    return file_with_path_no_ext, ext