from flask_login import current_user
from flask import render_template, url_for, abort, flash, redirect
from itsdangerous import URLSafeTimedSerializer

from . import app, mail, login_manager
from .models import User

from functools import wraps


###
### Required Roles Decorator (@)
###
def required_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapped
    return wrapper

##
## Check Unconfirmed User Decorator (@)
##
def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.email_confirmed is False:
            flash('Please confirm your email! Check your inbox.', 'error')
            return redirect(url_for('user_unconfirmed'))
        return func(*args, **kwargs)
    return decorated_function


###
### Login Manager
###
@login_manager.user_loader
def load_user(user):
    return User.query.filter_by(user=user).first()



###
### Send Confirmation Email
###
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

def send_confirm_email(user):
    token = ts.dumps(user.email, salt=app.config['RECOVER_EMAIL_SALT'])
    confirm_url = url_for('activate', token=token, _external=True)
    subject = 'BrewCalc App Email Confirmation'
    html = render_template('confirm-email.html', first_name=user.first_name, last_name=user.last_name, confirm_url=confirm_url)
    mail.send_email(subject=subject, to_email=[{'email': user.email}], html=html)


def send_reset_email(user):
    token = ts.dumps(user.email, salt=app.config['RECOVER_EMAIL_SALT'])
    reset_url = url_for('reset_with_token', token=token, _external=True)
    subject = 'Passoword reset requested'
    html = render_template('reset-password-email.html', first_name=user.first_name, last_name=user.last_name, reset_url=reset_url)
    mail.send_email(subject=subject, to_email=[{'email': user.email}], html=html)


def send_change_email(user):
    token = ts.dumps(user.unconfirmed_email, salt=app.config['RECOVER_EMAIL_SALT'])
    change_url = url_for('email_change', token=token, _external=True)
    subject = 'Email Change Confirmation'
    html = render_template('confirm-email-change.html', first_name=user.first_name, last_name=user.last_name, change_url=change_url)
    mail.send_email(subject=subject, to_email=[{'email': user.email}], html=html)


def confirmed_email(token):
    try:
        email = ts.loads(token, salt=app.config['RECOVER_EMAIL_SALT'], max_age=86400)
        return email
    except:
        return abort(404)

