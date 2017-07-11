from flask_login import current_user
from flask import render_template, url_for, abort
from itsdangerous import URLSafeTimedSerializer

from . import app, mail, login_manager
from .models import User

from functools import wraps


###
### Required Roles
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
    html = render_template('confirm_email.html', first_name=user.first_name, last_name=user.last_name, confirm_url=confirm_url)
    mail.send_email(subject=subject, to_email=[{'email': user.email}], html=html)
    print('after mail.send_email')


def confirmed_email(token):
    try:
        email = ts.loads(token, salt=app.config['RECOVER_EMAIL_SALT'], max_age=86400)
        return email
    except:
        return abort(404)