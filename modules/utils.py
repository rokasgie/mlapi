import ast
import logging
import re
import traceback
from configparser import ConfigParser

import pyzm.helpers.utils as pyzmutils

logger = logging.getLogger()


def str2tuple(str):
    m = [tuple(map(int, x.strip().split(','))) for x in str.split(' ')]
    if len(m) < 3:
        raise ValueError('{} formed an invalid polygon. Needs to have at least 3 points'.format(m))
    else:
        return m


# credit: https://stackoverflow.com/a/5320179
def findWholeWord(w):
    return re.compile(r'\b({0})\b'.format(w), flags=re.IGNORECASE).search


def check_and_import_zones(api, config):
    url = '{}/api/zones.json'.format(config.global_config.get('portal'))
    try:
        j = api._make_request(url=url, type='get')
    except Exception as e:
        logger.error('Zone API error: {}'.format(e))
        return

    for item in j.get('zones'):
        mid = str(item['Zone']['MonitorId'])

        # if we have a 'no' inside local monitor section, don't import 
        if mid in config.monitor_config and config.monitor_config[mid].get('import_zm_zones') == 'no':
            logger.debug('Not importing zones for monitor:{} as the monitor specific section says no'.format(
                mid))
            continue
            # else if global is no, and there is no local, don't import
        elif config.global_config['import_zm_zones'] == 'no' and (
                mid not in config.monitor_config or not config.monitor_config[mid].get('import_zm_zones')):
            logger.debug(
                'Not importing zone:{} for monitor:{} as the global setting says no and there is no local override'.format(
                    item['Zone']['Name'], mid))
            continue

        # At this stage, global is 'yes' and local is either unspecified or has 'yes'
        if mid not in config.monitor_config.keys():
            config.monitor_config[mid] = {}
            config.monitor_zone_patterns[mid] = {}
            config.monitor_polygons[mid] = []

        if item['Zone']['Type'] == 'Inactive':
            logger.debug('Skipping {} as it is inactive'.format(item['Zone']['Name']))
            continue

        item['Zone']['Name'] = item['Zone']['Name'].replace(' ', '_').lower()
        logger.debug('For monitor:{} importing zoneminder polygon: {} [{}]'.format(mid, item['Zone']['Name'],
                                                                                   item['Zone']['Coords']))
        config.monitor_polygons[mid].append({
            'name': item['Zone']['Name'],
            'value': str2tuple(item['Zone']['Coords']),
            'pattern': None
        })

    # Now copy over pending zone patterns from process_config
    for mid in config.monitor_polygons:
        for poly in config.monitor_polygons[mid]:
            for zone_name in config.monitor_zone_patterns[mid]:
                if poly['name'] == zone_name:
                    poly['pattern'] = config.monitor_zone_patterns[mid][zone_name]
                    logger.debug(
                        'For monitor:{} replacing match pattern for polygon:{} with: {}'.format(
                            mid, poly['name'], poly['pattern'])
                    )
    return config


def convert_config_to_ml_sequence(config):
    ml_options = {}

    for ds in config.global_config['detection_sequence']:
        if ds == 'object':

            ml_options['object'] = {
                'general': {
                    'pattern': config.global_config['object_detection_pattern'],
                    'disable_locks': config.global_config['disable_locks'],
                    'same_model_sequence_strategy': 'first'  # 'first' 'most', 'most_unique'

                },
                'sequence': [{
                    'tpu_max_processes': config.global_config['tpu_max_processes'],
                    'tpu_max_lock_wait': config.global_config['tpu_max_lock_wait'],
                    'gpu_max_processes': config.global_config['gpu_max_processes'],
                    'gpu_max_lock_wait': config.global_config['gpu_max_lock_wait'],
                    'cpu_max_processes': config.global_config['cpu_max_processes'],
                    'cpu_max_lock_wait': config.global_config['cpu_max_lock_wait'],
                    'max_detection_size': config.global_config['max_detection_size'],
                    'object_config': config.global_config['object_config'],
                    'object_weights': config.global_config['object_weights'],
                    'object_labels': config.global_config['object_labels'],
                    'object_min_confidence': config.global_config['object_min_confidence'],
                    'object_framework': config.global_config['object_framework'],
                    'object_processor': config.global_config['object_processor'],
                }]
            }
        elif ds == 'face':
            ml_options['face'] = {
                'general': {
                    'pattern': config.global_config['face_detection_pattern'],
                    'same_model_sequence_strategy': 'first',
                    #    'pre_existing_labels':['person'],
                },
                'sequence': [{
                    'tpu_max_processes': config.global_config['tpu_max_processes'],
                    'tpu_max_lock_wait': config.global_config['tpu_max_lock_wait'],
                    'gpu_max_processes': config.global_config['gpu_max_processes'],
                    'gpu_max_lock_wait': config.global_config['gpu_max_lock_wait'],
                    'cpu_max_processes': config.global_config['cpu_max_processes'],
                    'cpu_max_lock_wait': config.global_config['cpu_max_lock_wait'],
                    'face_detection_framework': config.global_config['face_detection_framework'],
                    'face_recognition_framework': config.global_config['face_recognition_framework'],
                    'face_processor': config.global_config['face_processor'],
                    'known_images_path': config.global_config['known_images_path'],
                    'face_model': config.global_config['face_model'],
                    'face_train_model': config.global_config['face_train_model'],
                    'unknown_images_path': config.global_config['unknown_images_path'],
                    'unknown_face_name': config.global_config['unknown_face_name'],
                    'save_unknown_faces': config.global_config['save_unknown_faces'],
                    'save_unknown_faces_leeway_pixels': config.global_config['save_unknown_faces_leeway_pixels'],
                    'face_recog_dist_threshold': config.global_config['face_recog_dist_threshold'],
                    'face_num_jitters': config.global_config['face_num_jitters'],
                    'face_upsample_times': config.global_config['face_upsample_times']
                }]

            }
        elif ds == 'alpr':
            ml_options['alpr'] = {
                'general': {
                    'pattern': config.global_config['alpr_detection_pattern'],
                    'same_model_sequence_strategy': 'first',
                    #    'pre_existing_labels':['person'],
                },
                'sequence': [{
                    'tpu_max_processes': config.global_config['tpu_max_processes'],
                    'tpu_max_lock_wait': config.global_config['tpu_max_lock_wait'],
                    'gpu_max_processes': config.global_config['gpu_max_processes'],
                    'gpu_max_lock_wait': config.global_config['gpu_max_lock_wait'],
                    'cpu_max_processes': config.global_config['cpu_max_processes'],
                    'cpu_max_lock_wait': config.global_config['cpu_max_lock_wait'],
                    'alpr_service': config.global_config['alpr_service'],
                    'alpr_url': config.global_config['alpr_url'],
                    'alpr_key': config.global_config['alpr_key'],
                    'alpr_api_type': config.global_config['alpr_api_type'],
                    'platerec_stats': config.global_config['platerec_stats'],
                    'platerec_regions': config.global_config['platerec_regions'],
                    'platerec_min_dscore': config.global_config['platerec_min_dscore'],
                    'platerec_min_score': config.global_config['platerec_min_score'],
                    'openalpr_recognize_vehicle': config.global_config['openalpr_recognize_vehicle'],
                    'openalpr_country': config.global_config['openalpr_country'],
                    'openalpr_state': config.global_config['openalpr_state'],
                    'openalpr_min_confidence': config.global_config['openalpr_min_confidence'],
                    'openalpr_cmdline_binary': config.global_config['openalpr_cmdline_binary'],
                    'openalpr_cmdline_params': config.global_config['openalpr_cmdline_params'],
                    'openalpr_cmdline_min_confidence': config.global_config['openalpr_cmdline_min_confidence'],
                }]

            }
    ml_options['general'] = {
        'model_sequence': ','.join(str(e) for e in config.global_config['detection_sequence'])
    }
    if config.global_config['detection_mode'] == 'all':
        logger.debug(3, 'Changing detection_mode from all to most_models to adapt to new features')
        config.global_config['detection_mode'] = 'most_models'
    return ml_options


def str_split(my_str):
    return [x.strip() for x in my_str.split(',')]


def process_config(args, config):
    # parse config file into a dictionary with defaults

    config.global_config = {}

    has_secrets = False
    secrets_file = None

    def _correct_type(val, t):
        if t == 'int':
            return int(val)
        elif t == 'eval' or t == 'dict':
            return ast.literal_eval(val) if val else None
        elif t == 'str_split':
            return str_split(val) if val else None
        elif t == 'string':
            return val
        elif t == 'float':
            return float(val)
        else:
            logger.error('Unknown conversion type {} for config key:{}'.format(e['type'], e['key']))
            return val

    def _set_config_val(k, v):
        # internal function to parse all keys
        val = config_file[v['section']].get(k, v['default'])

        if val and val[0] == '!':  # its a secret token, so replace
            logger.debug('Secret token found in config: {}'.format(val));
            if not has_secrets:
                raise ValueError('Secret token found, but no secret file specified')
            if secrets_file.has_option('secrets', val[1:]):
                vn = secrets_file.get('secrets', val[1:])
                # logger.debug (1,'Replacing {} with {}'.format(val,vn))
                val = vn
            else:
                raise ValueError('secret token {} not found in secrets file {}'.format(val, secrets_filename))

        config.global_config[k] = _correct_type(val, v['type'])
        if k.find('password') == -1:
            dval = config.global_config[k]
        else:
            dval = '***********'

    # logger.debug (1,'Config: setting {} to {}'.format(k,dval))

    # main        
    try:
        config_file = ConfigParser(interpolation=None, inline_comment_prefixes='#')
        config_file.read(args['config'])

        config.global_config['pyzm_overrides'] = {}
        if config_file.has_option('general', 'pyzm_overrides'):
            pyzm_overrides = config_file.get('general', 'pyzm_overrides')
            config.global_config['pyzm_overrides'] = ast.literal_eval(pyzm_overrides) if pyzm_overrides else {}
            if args.get('debug'):
                config.global_config['pyzm_overrides']['dump_console'] = True
                config.global_config['pyzm_overrides']['log_debug'] = True
                config.global_config['pyzm_overrides']['log_level_debug'] = 5
                config.global_config['pyzm_overrides']['log_debug_target'] = None

        logger.info('Reading config from: {}'.format(args.get('config')))
        if config_file.has_option('general', 'secrets'):
            secrets_filename = config_file.get('general', 'secrets')
            config.global_config['secrets'] = secrets_filename
            logger.info('Reading secrets from: {}'.format(secrets_filename))
            has_secrets = True
            secrets_file = ConfigParser(interpolation=None, inline_comment_prefixes='#')
            try:
                with open(secrets_filename) as f:
                    secrets_file.read_file(f)
            except:
                raise
        else:
            logger.debug('No secrets file configured')
        # now read config values

        config.polygons = []
        # first, fill in config with default values
        for k, v in config.config_vals.items():
            val = v.get('default', None)
            config.global_config[k] = _correct_type(val, v['type'])
            # print ('{}={}'.format(k,g.config[k]))

        # now iterate the file
        for sec in config_file.sections():
            if sec == 'secrets':
                continue

            # Move monitor specific stuff to a different structure
            if sec.lower().startswith('monitor-'):
                ts = sec.split('-')
                if len(ts) != 2:
                    logger.error(
                        'Skipping section:{} - could not derive monitor name. Expecting monitor-NUM format')
                    continue

                mid = ts[1]
                logger.debug('Found monitor specific section for monitor: {}'.format(mid))

                config.monitor_polygons[mid] = []
                config.monitor_config[mid] = {}
                config.monitor_zone_patterns[mid] = {}
                # Copy the sequence into each monitor because when we do variable subs
                # later, we will use this for monitor specific work
                try:
                    ml = config_file.get('ml', 'ml_sequence')
                    config.monitor_config[mid]['ml_sequence'] = ml
                except:
                    logger.debug('ml sequence not found in globals')

                try:
                    ss = config_file.get('ml', 'stream_sequence')
                    config.monitor_config[mid]['stream_sequence'] = ss
                except:
                    logger.debug('stream sequence not found in globals')

                for item in config_file[sec].items():
                    k = item[0]
                    v = item[1]
                    if k.endswith('_zone_detection_pattern'):
                        zone_name = k.split('_zone_detection_pattern')[0]
                        logger.debug('found zone specific pattern:{} storing'.format(zone_name))
                        config.monitor_zone_patterns[mid][zone_name] = v
                        continue
                    else:
                        if k in config.config_vals:
                            # This means its a legit config key that needs to be overriden
                            logger.debug('[{}] overrides key:{} with value:{}'.format(sec, k, v))
                            config.monitor_config[mid][k] = _correct_type(v, config.config_vals[k]['type'])
                        # config.monitor_config[mid].append({ 'key':k, 'value':_correct_type(v,g.config_vals[k]['type'])})
                        else:
                            if k.startswith(('object_', 'face_', 'alpr_')):
                                logger.debug('assuming {} is an ML sequence'.format(k))
                                config.monitor_config[mid][k] = v
                            else:
                                try:
                                    p = str2tuple(v)  # if not poly, exception will be thrown
                                    config.monitor_polygons[mid].append({'name': k, 'value': p, 'pattern': None})
                                    logger.debug('adding polygon: {} [{}]'.format(k, v))
                                except Exception as e:
                                    logger.debug(
                                        '{} is not a polygon, adding it as unknown string key'.format(
                                            k))
                                    config.monitor_config[mid][k] = v

                            # TBD only_triggered_zones

            # Not monitor specific stuff
            else:
                for (k, v) in config_file.items(sec):
                    if k in config.config_vals:
                        _set_config_val(k, config.config_vals[k])
                    else:
                        config.global_config[k] = v

                        # Parameter substitution

        logger.debug('Doing parameter substitution for globals')
        p = r'{{(\w+?)}}'
        for gk, gv in config.global_config.items():
            # input ('Continue')
            gv = '{}'.format(gv)
            # if not isinstance(gv, str):
            #    continue
            while True:
                matches = re.findall(p, gv)
                replaced = False
                for match_key in matches:
                    if match_key in config.global_config:
                        replaced = True
                        new_val = config.global_config[gk].replace('{{' + match_key + '}}',
                                                                   str(config.global_config[match_key]))
                        config.global_config[gk] = new_val
                        gv = new_val
                    else:
                        logger.debug('substitution key: {} not found'.format(match_key))
                if not replaced:
                    break

        logger.debug('Doing parameter substitution for monitor specific entities')
        p = r'{{(\w+?)}}'
        for mid in config.monitor_config:
            for key in config.monitor_config[mid]:
                # input ('Continue')
                gk = key
                gv = config.monitor_config[mid][key]
                gv = '{}'.format(gv)
                # if not isinstance(gv, str):
                #    continue
                while True:
                    matches = re.findall(p, gv)
                    replaced = False
                    for match_key in matches:
                        if match_key in config.monitor_config[mid]:
                            replaced = True
                            new_val = gv.replace('{{' + match_key + '}}', str(config.monitor_config[mid][match_key]))
                            gv = new_val
                            config.monitor_config[mid][key] = gv
                        elif match_key in config.global_config:
                            replaced = True
                            new_val = gv.replace('{{' + match_key + '}}', str(config.global_config[match_key]))
                            gv = new_val
                            config.monitor_config[mid][key] = gv
                        else:
                            logger.debug('substitution key: {} not found'.format(match_key))
                    if not replaced:
                        break

            secrets = pyzmutils.read_config(config.global_config['secrets'])
    except Exception as e:
        logger.error('Error parsing config:{}'.format(args['config']))
        logger.error('Error was:{}'.format(e))
        logger.fatal('error: Traceback:{}'.format(traceback.format_exc()))

    return config
