

import argparse
import logging

import cv2
from pyzm import __version__ as pyzm_version

from mlapi import get_app
from modules.__init__ import __version__
from modules.common_params import CONFIG

ap = argparse.ArgumentParser()
ap.add_argument('-c', '--config', help='config file with path', required=True)
ap.add_argument('-vv', '--verboseversion', action='store_true', help='print version and exit')
ap.add_argument('-v', '--version', action='store_true', help='print mlapi version and exit')
ap.add_argument('-d', '--debug', help='enables debug on console', action='store_true')
ap.add_argument('-g', '--gpu', type=int, help='specify which GPU to use if multiple are present')


def main(args):
    if args.version:
        print('{}'.format(__version__))
        return

    logging.info('--------| mlapi version:{}, pyzm version:{} |--------'.format(__version__, pyzm_version))

    cuda_device_count = cv2.cuda.getCudaEnabledDeviceCount()
    if cuda_device_count == 1:
        device_count_plural = ''
    else:
        device_count_plural = 's'

    logging.debug('{} CUDA-enabled device{} found'.format(cuda_device_count, device_count_plural))

    if args.gpu:
        selected_gpu = int(args.gpu)
        if selected_gpu in range(0, cuda_device_count):
            logging.debug('Using GPU #{}'.format(selected_gpu))
            cv2.cuda.setDevice(selected_gpu)
        else:
            logging.warning('Invalid CUDA GPU #{} selected, ignoring'.format(selected_gpu))
            if cuda_device_count > 1:
                logging.info('Valid options for GPU are 0-{}:'.format(cuda_device_count - 1))
                for cuda_device in range(0, cuda_device_count):
                    cv2.cuda.printShortCudaDeviceInfo(cuda_device)

    app = get_app(vars(args))

    if CONFIG.global_config['wsgi_server'] == 'bjoern':
        logging.info('Using bjoern as WSGI server')
        import bjoern

        bjoern.run(app, host='0.0.0.0', port=CONFIG.global_config['port'])
    else:
        logging.info('Using flask as WSGI server')
        logging.info('Starting server with max:{} processes'.format(CONFIG.global_config['processes']))
        app.run(
            host='0.0.0.0',
            port=CONFIG.global_config['port'],
            threaded=False,
            processes=CONFIG.global_config['processes'],
            debug=args.debug
        )


if __name__ == '__main__':
    args, u = ap.parse_known_args()
    main(args)
