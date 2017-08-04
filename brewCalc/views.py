## BrewCalc App ##
## Author: Claudio Castello

## Flask Imports ##
from flask import request, abort, render_template, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user

## App Imports ##
from . import app, db, login_manager, admin
from .forms import (LoginForm, CreateForm, EditForm, EditFormSocial,
                    SendEmailResetForm, ResendConfirmForm, ResetPasswordForm,
                    DeleteProfileForm, DeleteProfileFormSocial)
from .models import User
from .utils import (required_roles, send_email_generic, confirmed_email,
                    check_confirmed, google, facebook, twitter,
                    edit_profile_generic, delete_profile_generic)

# Flask-Admin
from flask_admin.contrib.sqla import ModelView
admin.add_view(ModelView(User, db.session))

##
## Index
##
@app.route('/', methods=['GET'])
@login_required
@check_confirmed
def index():
    '''
    Checks if there is an authenticated user and render index.html if True
    If False, redirects to 'login'
    '''

    if current_user.is_authenticated:
        return render_template('index.html')
    return redirect(url_for('login'))

##
## Login and logout
##

## Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
    This view is used to log in a registered user.
    '''
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        # The if/else below checks if user is trying to login with the username or email.
        if '@' in form.user.data:
            user = User.query.filter_by(email=form.user.data).first()
            # If user registered with Google the app ask him to log through Google authentication.
            if user and user.isGoogleUser:
                flash('Use your Google Account (link below) to login.', 'error')
                return redirect(url_for('login'))
        else:
            user = User.query.filter_by(user=form.user.data).first()

        if user and user.is_password_correct(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect(url_for('index'))
        else:
            flash('Incorrect username/email or password', 'error')
    return render_template('login.html', form=form)


##########################################################################################
#################################### Google Login ########################################
##########################################################################################

@app.route('/google-login')
def google_login():
    '''
    Checks if there is a google_token in session and log user in.
    '''
    # Check if there is a Google Token in session
    if 'google_token' in session:
        # If there is, get Google user info and query User by user email.
        google_user_info = google.get('userinfo')
        user = User.query.filter_by(email=google_user_info.data['email']).first()
        # If user is not found, create a new user with Google userinfo.
        # There is no confirmation email for the user in this case (email_confirmed = True).
        # isGoogleUser is set to True
        if user is None:
            user = User(user=google_user_info.data['email'], 
                        email=google_user_info.data['email'], 
                        role='user', 
                        first_name=google_user_info.data['given_name'], 
                        last_name=google_user_info.data['family_name'], 
                        email_confirmed=True,
                        isGoogleUser=True,
                        googleID=google_user_info.data['id'])
            db.session.add(user)
            db.session.commit()
        # if user is found or created, log the user in and redirects to 'index'
        login_user(user)
        return redirect(url_for('index'))
    # If there is not a Google Token in session, redirects to 'authorized' to get
    # user authorization to use Google account and log in.
    return google.authorize(callback=url_for('google_authorized', _external=True))


@app.route('/google-logout')
def google_logout():
    '''
    Pop google_token from session. Trying to figure out when to use.
    '''
    session.pop('google_token', None)
    return redirect(url_for('index'))


@app.route('/oauth2callback')
def google_authorized():
    '''
    Request user authorization to use Google account
    to create user and/or login with it in the app.
    '''
    resp = google.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    return redirect(url_for('google_login'))


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

##########################################################################################
##########################################################################################
##########################################################################################

##########################################################################################
################################### Facebook Login #######################################
##########################################################################################

# Views here follows the same principles of Google login.

@app.route('/facebook-login')
def facebook_login():
    '''
    Checks if there is a facebook_token in session and log user in.
    '''
    # Check if there is a Facebook Token in session
    if 'facebook_token' in session:
        # If there is, get Facebook user info and query User by user facebookID.
        facebook_user_info = facebook.get('me')
        user = User.query.filter_by(facebookID=facebook_user_info.data['id']).first()
        # If user is not found, create a new user with Facebook userinfo.
        # There is no confirmation email for the user in this case (email_confirmed = True).
        # isFacebookUser is set to True
        if user is None:
            first_name = facebook_user_info.data['name'].split(' ')[0]
            last_name = facebook_user_info.data['name'].split(' ')[-1]
            facebookID = facebook_user_info.data['id']
            email = first_name+facebookID+'@'+'facebook.com' # Mock email as I couldn't retrieve user Facebook email yet...
            user = User(user=first_name+facebookID, 
                        email=email, 
                        role='user', 
                        first_name=first_name, 
                        last_name=last_name, 
                        email_confirmed=True,
                        isFacebookUser=True,
                        facebookID=facebookID)
            db.session.add(user)
            db.session.commit()
        # if user is found or created, log the user in and redirects to 'index'
        login_user(user)
        return redirect(url_for('index'))
    # If there is not a Facebook Token in session, redirects to 'facebook_authorized' to get
    # user authorization to use Facebook account and log in.
    return facebook.authorize(callback=url_for('facebook_authorized',
                              next=request.args.get('next') or request.referrer or None,
                              _external=True))


@app.route('/login/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    '''
    Request user authorization to use Facebook account
    to create user and/or login with it in the app.
    '''
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['facebook_token'] = (resp['access_token'], '')
    return redirect(url_for('facebook_login'))


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('facebook_token')

##########################################################################################
##########################################################################################
##########################################################################################

##########################################################################################
################################### Twitter Login ########################################
##########################################################################################

@app.route('/twitter-login')
def twitter_login():
    '''
    Checks if there is a twitter_token in session and log user in.
    '''
    # Check if there is a Twitter Token in session
    if 'twitter_token' in session:
        # If there is, get Facebook user info and query User by user twitterID.
        twitter_user_info = session['twitter_token']
        user = User.query.filter_by(twitterID=twitter_user_info['user_id']).first()
        # If user is not found, create a new user with Twitter userinfo.
        # There is no confirmation email for the user in this case (email_confirmed = True).
        # isTwitterUser is set to True
        if user is None:
            first_name = twitter_user_info['screen_name']
            last_name = 'TwitterUser'
            twitterID = twitter_user_info['user_id']
            email = first_name + twitterID + '@twitter.com' # Mock email...
            user = User(user=first_name + twitterID, 
                        email=email, 
                        role='user', 
                        first_name=first_name, 
                        last_name=last_name, 
                        email_confirmed=True,
                        isTwitterUser=True,
                        twitterID=twitterID)
            db.session.add(user)
            db.session.commit()
        # if user is found or created, log the user in and redirects to 'index'
        login_user(user)
        return redirect(url_for('index'))
    # If there is not a Twitter Token in session, redirects to 'twitter_authorized' to get
    # user authorization to use Twitter account and log in.
    return twitter.authorize(callback=url_for('twitter_authorized',
                             next=request.args.get('next') or request.referrer or None,
                             _external=True))


@app.route('/twitter-authorized')
def twitter_authorized():
    '''
    Request user authorization to use Facebook account
    to create user and/or login with it in the app.
    '''
    resp = twitter.authorized_response()
    if resp is None:
        flash('You denied access to sign in!', 'error')
    else:
        session['twitter_token'] = resp
    return redirect(url_for('twitter_login'))


@twitter.tokengetter
def get_twitter_oauth_token():
    return session.get('twitter_oauth')


@app.route('/twitter-logout')
def twitter_logout():
    session.pop('twitter_oauth', None)
    return redirect(url_for('index'))

##########################################################################################
##########################################################################################
##########################################################################################

## Logout
@app.route('/logout')
def logout():
    '''
    Simply clear session and log out the current user.
    '''
    session.clear()
    logout_user()
    return redirect(url_for('index'))

##
## Create User Profile
##

## Create User
@app.route('/create', methods=['GET', 'POST'])
def create():
    '''
    This view creates a new user profile. Not used when user choose to login with Google.
    '''
    form = CreateForm()
    if form.validate_on_submit():
        # Checking if username is available
        if User.query.filter_by(user=form.user.data).first() is None:
            # Cheking if email is not in use by another user
            if User.query.filter_by(email=form.email.data).first() is None:
                # If username and email are available, create the new user and send email for confirmation.
                # By default the role will be 'user' and 'confirmed_email' will be False (see models.py).
                # 'confirmed_email' = False do not allow user to navigate and keep asking for confirming email.
                user = User(user=form.user.data,
                            password=form.password.data, 
                            email=form.email.data, role='user', 
                            first_name=form.first_name.data, 
                            last_name=form.last_name.data, 
                            unconfirmed_email=form.email.data)
                db.session.add(user)
                db.session.commit()
                send_email_generic(user=user,
                                   user_email=user.email, 
                                   action_url='activate', 
                                   email_subject='BrewCalc App Email Confirmation', 
                                   message_template='confirm-email.html')
                flash('New account created! You will receive a confirmation email.', 'success')
                return redirect(url_for('login'))
            else:
                if User.query.filter_by(email=form.email.data).first().isGoogleUser:
                    flash('Try to log in with your Google Account!', 'error')
                    return redirect(url_for('login'))
                flash('Email address already in our database. Please use another email to proceed.', 'error')
        else:
            flash('Username already taken. Choose another one.', 'error')
    return render_template('create.html', form=form)


## Confirm New User
@app.route('/activate/<token>', methods=['GET', 'POST'])
def activate(token):
    '''
    After clicking the activation link sent in the confirmation email
    this view change the user status to confirmed.
    '''
    # Retrieve user email address passing the token to confirmed_email function (see utils.py)
    # If wrong or expired token, email = None
    email = confirmed_email(token)
    # Query user filtering by email and passing email defined above as parameter
    # If user not find in database, user = None and a redirect to index take place
    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('It was not possible to find your email address in our database.', 'error')
        return redirect(url_for('index'))
    # If user found, set the parameter email_confirmed to True, allowing user to navigate the app.
    user.email_confirmed = True
    user.unconfirmed_email = None
    db.session.add(user)
    db.session.commit()
    flash('You confirmed your email address.', 'success')
    return redirect(url_for('login'))


## Unconfirmed User
@app.route('/user-unconfirmed', methods=['GET', 'POST'])
@login_required
def user_unconfirmed():
    '''
    If users do not confirm their email address, they will not be allowed to navigate the app.
    This view provide the interface to resend confirmation email to the registered email address.
    '''
    user = current_user
    form = ResendConfirmForm()
    return render_template('user_unconfirmed.html', form=form, user=user)


## Resend Confirmation Email
@app.route('/resend-confirmation', methods=['GET', 'POST'])
@login_required
def resend_confirmation():
    '''
    If for some reason the users didn't receive the first confirmation email  or the this view
    token is expired allows them to click a button and resend the confirmation message to the
    registered email. It's not possible to change the email address as it is not confirmed.
    '''
    user = current_user
    print(user, user.email)
    send_email_generic(user=user,
                       user_email=user.email, 
                       action_url='activate', 
                       email_subject='BrewCalc App New Email Confirmation', 
                       message_template='confirm-email.html')
    flash('You will receive a new confirmation email.', 'success')
    return redirect(url_for('logout'))
    

##
## Reset password
##

## Send Request for Password Reset
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    '''
    This view provide users with a reset password tool and
    only confirmed users can request this password reset.
    Users who logged in with Google are not able to reset password
    as they don't have one.
    '''
    form = SendEmailResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # If users logged in with Google/Facebook they can't reset password.
            if user.isGoogleUser or user.isFacebookUser or user.isTwitterUser:
                flash('Try to log in with your Google/Facebook Account!', 'error')
                return redirect(url_for('login'))
            if user.email_confirmed == True:
                # Users can send an email requesting a reset in their password; only confirmed users are able to do this.
                send_email_generic(user=user,
                                   user_email=user.email, 
                                   action_url='reset_with_token', 
                                   email_subject='Password Reset Requested', 
                                   message_template='reset-password-email.html')
                flash('A message was sent to your email with instructions.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Your email is not confirmed yet... check your inbox for confirmation email', 'error')
        else:
            flash('This email is not registered. Please create a profile for you', 'error')
    return render_template('reset-password.html', form=form)


## Set New Password
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    '''
    After receiving the reset email and clicking the reset link, user are redirected to 
    this view to set a new password for their accounts.
    '''
    # User email is retrieved by passing the token to confirmed_email function (see utils.py)
    # If wrong or expired token, email = None
    email = confirmed_email(token)
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Query user filtering by email and passing email defined above as parameter
        # If user not find in database, user = None and a redirect to index take place
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash('It was not possible to find your email address in our database.', 'error')
            return redirect(url_for('index'))
        # If user is found, set_new_password() method is called on user
        # with data from form passed as argument (see User Class at models.py)
        user.set_new_password(form.new_password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your password was redefined.', 'success')
        return redirect(url_for('login'))
    return render_template('reset-new-password.html', form=form, token=token)


##
## User Profile / Edit Profile / Delete Profile
##

## Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@check_confirmed
def profile():
    '''
    This view allow users to edit their profiles. It's possible to change first_name, last_name,
    and password straight from the form. If users wants to change email address it will be necessary
    an email confirmation. In any case is necessary to provide the current password in order to save
    changes.

    If user logged in with Google/Facebook it is only possible to change first_name and last_name.
    '''
    # Get current user and pass as object to EditForm or EditFormSocial classes in the instantiation,
    # providing form fields with pre-loaded information about the user.
    user = current_user
    # Define the 'social' variable to False to render all fields in profile.html
    # when user's not logged with Google/Facebook
    social = False
    if user.isGoogleUser or user.isFacebookUser or user.isTwitterUser:
        # If user logged with Google/Facebook/Twitter, social = True and template will be
        # rendered only with first name and last name fields (see templates/profile.html)
        # User do not have password and is_password_correct is set to True
        # new_email and new_password are set to None because user is not able to change
        # these properties and utils.py will go through the right path.
        social = True
        form = EditFormSocial(obj=user)
        is_password_correct = True
        new_email = None
        new_password = None
    else:
        # In case users are not logged with Facebook/Google they need to type their
        # password to save changes.
        # new_email and new_password, if provided, are get from form fields.
        form = EditForm(obj=user)
        new_email = form.email.data
        new_password = form.new_password.data

    # Validate form on submit and pass arguments to edit_profile_generic (see utils.py)
    if form.validate_on_submit():
        if not social:
            is_password_correct = user.is_password_correct(form.old_password.data)
        if is_password_correct:
            edit_profile_generic(user=user, 
                                 first_name=form.first_name.data, 
                                 last_name=form.last_name.data, 
                                 email=new_email, 
                                 new_password=new_password)
        else:
            flash('Incorret password', 'error')
    return render_template('profile.html', form=form, user=user, social=social)


## Email Change
@app.route('/email-change/<token>', methods=['GET', 'POST'])
def email_change(token):
    '''
    This view confirms the email change request and stores the old email
    address as an unconfirmed_email in case user wants to revert the change.
    Only available for users who didn't log in with Google/Facebook.
    '''
    # New user email is retrieved by passing the token to confirmed_email function (see utils.py)
    # If wrong or expired token, email = None
    new_email = confirmed_email(token)
    # Query user filtering by unconfirmed_email and passing new_email defined above as parameter
    # If user not find in database, user = None and a redirect to 'create' take place.
    #
    # When user is None it means that the unauthorized_email_change view took place before this one.
    user = User.query.filter_by(unconfirmed_email=new_email).first()
    if user is None:
        flash('This email change is not authorized! Create a new profile for yourself', 'error')
        return redirect(url_for('create'))
    # Email change requested and confirmed with new email address.
    # A new email is sent to old email address to revert changes in case of fraud.
    # This new email, if link clicked, made user.unconfirmed_email = None and set user.email
    # to the old email address, cancelling changes and avoiding unauthorized email changes.
    send_email_generic(user=user, 
                       email=user.email, 
                       action_url='unauthorized_email_change', 
                       email_subject='Email Change Requested', 
                       message_template='unauthorized-change.html')
    # The unconfirmed email is set to the old email address
    # and user.email is set to the new email address.
    user.unconfirmed_email = user.get_email()
    user.email = new_email
    db.session.add(user)
    db.session.commit()
    flash('Email changed successfully. A confirmation was sent to the old email address.', 'success')
    return redirect(url_for('login'))

## Unauthorized Email Change
@app.route('/unauthorized-change/<token>', methods=['GET', 'POST'])
def unauthorized_email_change(token):
    '''
    This view provides a way to reverse an unauthorized email change,
    setting the user email to the previous one (before change request)
    '''
    # After email change take place with email_change view, an email is sent to the
    # old email address to prevent unauthorized email changes.
    # Old user email is retrieved by passing the token to confirmed_email function (see utils.py)
    # If wrong or expired token, email = None
    old_email = confirmed_email(token)
    # Query user filtering by confirmed_email and passing old_email defined above as parameter.
    # If user not find in database the email change confirmation didn't take place yet,
    # if user = None a query is made filtering by unconfirmed_email, meaning that email change took place.
    user = User.query.filter_by(email=old_email).first()
    if user is None: # user will be None if the email was changed by email_change view.
        user = User.query.filter_by(unconfirmed_email=old_email).first()
    # User email is set to old_email address and unconfirmed_email is set to None to prevent
    # that a click in the email_change link sent changes email again (see email_change() view)
    user.email = old_email
    user.unconfirmed_email = None
    db.session.add(user)
    db.session.commit()
    flash('Your email address was not changed.', 'success')
    return redirect(url_for('login'))


## Delete Profile
@app.route('/delete-profile', methods=['GET', 'POST'])
@login_required
@check_confirmed
def delete_profile():
    '''
    This view simply checks username, email, password and a checkbox
    before deleting an user profile. These steps exist only to ensure
    the users really want to delete their profiles.

    If users logged in with Google/Facebook, the view only checks if checkbox is checked.
    '''
    user = current_user
    delete_requested = False
    social = False

    # Check if is a Google/Facebook user or not to instantiate the correct form
    # and define is_password_correct and social variables.
    if user.isGoogleUser or user.isFacebookUser or user.isTwitterUser:
        form = DeleteProfileFormSocial()
        is_password_correct = True
        social = True
        username = user.user
        user_email = user.email
    else:
        form = DeleteProfileForm()
        is_password_correct = user.is_password_correct(form.password.data)
        username = form.user.data
        user_email = form.email.data
    # If form is validated calls delete_profile_generic() to request
    # profile deletion (see utils.py for this function defeinition)
    if form.validate_on_submit():
        if is_password_correct:
            delete_requested = delete_profile_generic(user=user,
                                                      username=username,
                                                      user_email=user_email,
                                                      checked_box=form.confirm_delete.data)
        else:
            flash('Incorrect password', 'error')
    # If all fields are correct delete_profile_generic() will send email
    # for profile deletion confirmation and return True. The user is logged
    # out and redirected to index'. Users logged with Facebook will not get
    # this confirmation email and Profile will be deleted immediatelly.
    if delete_requested:
        flash('You will receive an email to confirm profile deletion (no email for users logged with Facebook/Twitter)', 'success')
        logout_user()
        return redirect(url_for('index'))
    return render_template('delete-profile.html', form=form, user=user, social=social)


## Confirm Delete Profile
@app.route('/confirm-delete/<token>', methods=['GET', 'POST'])
def confirm_delete_user(token):
    '''
    This view confirms deletion of user profile.
    '''
    # User email is retrieved by passing the token to confirmed_email function (see utils.py)
    # If wrong or expired token, email = None
    email = confirmed_email(token)
    # Query user filtering by unconfirmed_email and passing new_email defined above as parameter
    # If user not find in database, user = None and a redirect to 'index' take place.
    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('It was not possible to find your email address in our database.', 'error')
        return redirect(url_for('index'))
    db.session.delete(user)
    db.session.commit()
    flash('Profile Deleted', 'success')
    return redirect(url_for('index'))




#####################################################################################################################################

## Recipe related views
@app.route('/recipes', methods=['GET'])
@login_required
@check_confirmed
def recipes():
    return render_template('recipes.html')