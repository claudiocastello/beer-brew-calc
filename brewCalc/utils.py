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
    '''
    This simple snippet is used to define which roles will be able to access some
    pages in the application. In the future a Flask-Principal instance will be used
    to manage this, but for now this one is good.
    '''
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
    '''
    This decorator is used to grant or not access to pages in application
    depending on the user confirmed email status. If confirmed is True, user
    can access pages, otherwise user_unconfirmed page will be shown.
    '''
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
    '''
    User loader required by login_manager.
    '''
    return User.query.filter_by(user=user).first()



###
### Send Confirmation Email
###

# Instantiation of URLSafeTimedSerializer object, responsible for generation 
# of a random string for user email when dumps is called on it and to retrieve
# the user email when loads is called on it.
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def send_email_generic(user, user_email, url, subject, template_to_render):
    '''
    This function is used to send an email to users with a tokenized URL (/url/<token>)
    for email verification purposes. The function takes as arguments the user object,
    user_email, url of verification, email subject and the template to render as message.
    '''
    token = ts.dumps(user_email, salt=app.config['RECOVER_EMAIL_SALT'])
    validation_url = url_for(url, token=token, _external=True)
    html = render_template(template_to_render, first_name=user.first_name, last_name=user.last_name, validation_url=validation_url)
    mail.send_email(subject=subject, to_email=[{'email': user_email}], html=html)


def confirmed_email(token):
    '''
    This function is called on the click of the confirmation email and takes the token
    to retrieve users email. The email is then confirmed and the action takes places.
    '''
    try:
        email = ts.loads(token, salt=app.config['RECOVER_EMAIL_SALT'], max_age=86400)
        return email
    except:
        return None

