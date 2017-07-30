from flask_login import current_user
from flask import render_template, url_for, abort, flash, redirect

from itsdangerous import URLSafeTimedSerializer

from . import app, db, mail, login_manager, oauth
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


##
## Google Login
##
google = oauth.remote_app('google',
                          consumer_key=app.config.get('GOOGLE_CLIENT_ID'),
                          consumer_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
                          request_token_params={'scope': 'email'},
                          base_url='https://www.googleapis.com/oauth2/v1/',
                          request_token_url=None,
                          access_token_method='POST',
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          authorize_url='https://accounts.google.com/o/oauth2/auth')



##
## Facebook Login
##
facebook = oauth.remote_app('facebook',
                            base_url='https://graph.facebook.com/',
                            request_token_url=None,
                            access_token_url='/oauth/access_token',
                            authorize_url='https://www.facebook.com/dialog/oauth',
                            consumer_key=app.config.get('FACEBOOK_APP_ID'),
                            consumer_secret=app.config.get('FACEBOOK_APP_SECRET'),
                            request_token_params={'scope': 'email'})


##
## Twitter Login
##
twitter = oauth.remote_app('twitter',
                           consumer_key=app.config.get('TWITTER_API_KEY'),
                           consumer_secret=app.config.get('TWITTER_API_SECRET'),
                           base_url='https://api.twitter.com/1.1/',
                           request_token_url='https://api.twitter.com/oauth/request_token',
                           access_token_url='https://api.twitter.com/oauth/access_token',
                           authorize_url='https://api.twitter.com/oauth/authorize')



###
### Send Confirmation Email
###

# Instantiation of URLSafeTimedSerializer object, responsible for generation 
# of a random string for user email when dumps is called on it and to retrieve
# the user email when loads is called on it.
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def send_email_generic(user, user_email, action_url, email_subject, message_template):
    '''
    This function is used to send an email to users with a tokenized URL (/action_url/<token>)
    for email verification purposes. The function takes as arguments the user object,
    user_email, url of verification, email subject and the template to render as message.
    '''
    token = ts.dumps(user_email, salt=app.config['RECOVER_EMAIL_SALT'])
    validation_url = url_for(action_url, token=token, _external=True)
    html = render_template(message_template, first_name=user.first_name, last_name=user.last_name, validation_url=validation_url)
    mail.send_email(subject=email_subject, to_email=[{'email': user_email}], html=html)


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



##
## Edit Profile Generic
##
def edit_profile_generic(user, first_name, last_name, email, new_password):
    '''
    After implementing Google login this function replaced direct profile changes
    in views.py in order to avoid duplication of code. It changes user profile info
    according to user request.
    '''
    # Users first_name and last_name will be updated even if not changed.
    user.first_name = first_name
    user.last_name = last_name
    # Checks if email is not None (users must have a valid email address) and 
    # different from user current email to avoid requesting email change incorrectly.
    if email is not None and email != user.email:
        # Query database to check if the chosen email is not in use already.
        # If the pevious check was not done the app will find the user email
        # in database and incorrectly flash a message about it.
        if User.query.filter_by(email=email).first() is None:
            # Sets unconfirmed_email to the user new email.
            user.unconfirmed_email = email
            send_email_generic(user=user, 
                               user_email=user.unconfirmed_email, 
                               action_url='email_change', 
                               email_subject='Email Change Confirmation', 
                               message_template='confirm-email-change.html')
            flash('You need to confirm your new email address. A message was sent with instructions.', 'success')
        else:
            flash('This email address is already in use by another user. Choose another one.', 'error')
    # Check if the new passoword is not an empty string
    # or None and set it using set_new_password() method
    if new_password != '' and new_password is not None:
        user.set_new_password(new_password)
    db.session.commit()
    flash('Saved', 'success')


##
## Delete Profile Generic
##
def delete_profile_generic(user, username, user_email, checked_box):
    '''
    After implementing Google login this function replaced direct profile deletion
    in views.py in order to avoid duplication of code. It checks for user data
    confirmation before sending the confirmation email to delete profile.
    '''
    if user.get_email() == user_email:
        if user.get_id() == username:
            if checked_box:
                if user.isFacebookUser or user.isTwitterUser:
                    db.session.delete(user)
                    db.session.commit()
                    return True
                send_email_generic(user=user, 
                                   user_email=user.email, 
                                   action_url='confirm_delete_user', 
                                   email_subject='Delete Profile Request', 
                                   message_template='delete-profile-email.html')
                return True
            else:
                flash('Check to confirm profile exclusion', 'error')
                return False
        else:
            flash('Incorrect username address', 'error')
            return False
    else:
        flash('Incorrect email address', 'error')
        return False