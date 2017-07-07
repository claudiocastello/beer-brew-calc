import os

DEBUG = True
TESTING = True
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
WTF_CSRF_ENABLED = True
SECRET_KEY = os.environ.get('SECRET_KEY')