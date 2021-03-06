from sqlalchemy.ext.hybrid import hybrid_property

from . import app, db, bcrypt

import datetime

FIELD_MAX_LIM = {
    'user': 128,
    'password': 128,
    'email': 50,
    'role': 5,
    'first_name': 50,
    'last_name': 50,
    'locale': 5
}

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(FIELD_MAX_LIM['user']), unique=True, nullable=False)
    _password = db.Column(db.LargeBinary(FIELD_MAX_LIM['password']), nullable=True)
    email = db.Column(db.String(FIELD_MAX_LIM['email']), nullable=False)
    unconfirmed_email = db.Column(db.String(FIELD_MAX_LIM['email']), nullable=True, default=None)
    role = db.Column(db.String(FIELD_MAX_LIM['role']), nullable=False, default='user')
    first_name = db.Column(db.String(FIELD_MAX_LIM['first_name']), nullable=False)
    last_name = db.Column(db.String(FIELD_MAX_LIM['last_name']), nullable=False)
    locale = db.Column(db.String(FIELD_MAX_LIM['locale']), default='pt_BR')
    email_confirmed = db.Column(db.Boolean, nullable=False, default=False)

    ## Google UserInfo
    isGoogleUser = db.Column(db.Boolean, nullable=False, default=False)
    googleID = db.Column(db.String(), unique=True, nullable=True, default=None)

    ## Facebook UserInfo
    isFacebookUser = db.Column(db.Boolean, nullable=False, default=False)
    facebookID = db.Column(db.String(), unique=True, nullable=True, default=None)

    ## Twitter UserInfo
    isTwitterUser = db.Column(db.Boolean, nullable=False, default=False)
    twitterID = db.Column(db.String(), unique=True, nullable=True, default=None)


    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.user)

    def get_email(self):
        return str(self.email)

    def is_password_correct(self, plaintext):
        return bcrypt.check_password_hash(self.password, plaintext)

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def set_password(self, plaintext):
        self._password = bcrypt.generate_password_hash(plaintext)

    def set_new_password(self, plaintext):
        self._password = bcrypt.generate_password_hash(plaintext)

    def __repr__(self):
        return '({user}, {first_name} {last_name})'.format(user=self.user, first_name=self.first_name, last_name=self.last_name)