import os

DEBUG = True
TESTING = True
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
WTF_CSRF_ENABLED = True
SECRET_KEY = os.environ.get('SECRET_KEY')
RECOVER_EMAIL_SALT = os.environ.get('RECOVER_EMAIL_SALT')
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
SENDGRID_DEFAULT_FROM = os.environ.get('SENDGRID_DEFAULT_FROM')

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = os.environ.get('REDIRECT_URI')