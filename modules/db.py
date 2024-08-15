import getpass
import logging

from passlib.hash import bcrypt
from tinydb import TinyDB, Query, where


class Database:
    def __init__(self, config, prompt_to_create=True):
        self.__logger = logging.getLogger(__name__)
        self.__config = config

        self.db = self.__build_db(config.global_config['db_path'] + '/db.json')
        self.users = self.db.table('users')
        self.query = Query()
        self.__get_user(prompt_to_create)

        self.__logger.debug('DB engine ready')

    def _get_hash(self, password):
        return bcrypt.hash(password)

    def __build_db(self, db_name):
        self.__logger.debug('Opening DB at {}'.format(db_name))
        return TinyDB(db_name)

    def __get_user(self, prompt_to_create):
        if not len(self.users) and prompt_to_create:
            self.__logger.debug('Initializing default users')

            print('--------------- User Creation ------------')
            print('Please configure atleast one user:')
            while True:
                name = input('user name:')
                if not name:
                    print('Error: username needed')
                    continue
                p1 = getpass.getpass('Please enter password:')
                if not p1:
                    print('Error: password cannot be empty')
                    continue
                p2 = getpass.getpass('Please re-enter password:')
                if p1 != p2:
                    print('Passwords do not match, please re-try')
                    continue
                break
            self.users.insert({'name': name, 'password': self._get_hash(p1)})
            print('------- User: {} created ----------------'.format(name))

    def check_credentials(self, user, supplied_password):
        user_object = self.get_user(user)
        if not user_object:
            return False  # user doesn't exist
        stored_password_hash = user_object.get('password')

        if not bcrypt.verify(supplied_password, stored_password_hash):
            self.__logger.debug('Hashes do NOT match: incorrect password')
            return False
        else:
            self.__logger.debug('Hashes are correct: password matched')
            return True

    def get_all_users(self):
        return self.users.all()

    def get_user(self, user):
        return self.users.get(self.query.name == user)

    def delete_user(self, user):
        return self.users.remove(where('name') == user)

    def add_user(self, user, password):
        hashed_password = self._get_hash(password)
        return self.users.upsert({'name': user, 'password': hashed_password}, self.query.name == user)
