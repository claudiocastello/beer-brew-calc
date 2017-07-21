## BrewCalc App ##
## Author: Claudio Castello

## Flask Imports ##
from flask import request, abort, render_template, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user

## App Imports ##
from . import app, db, login_manager
from .forms import LoginForm, CreateForm, EditForm, EditFormSocial, SendEmailResetForm, ResendConfirmForm, ResetPasswordForm, DeleteProfileForm
from .models import User
from .utils import required_roles, send_email_generic, confirmed_email, check_confirmed, google


##
## Index
##
@app.route('/', methods=['GET'])
@login_required
@check_confirmed
def index():
    '''
    Checks if there is a authenticated user and render index.html if True
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
        # The if/else below just checks if user is trying to login with the username or email.
        if '@' in form.user.data:
            user = User.query.filter_by(email=form.user.data).first()
            if user.isGoogleUser:
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
    if 'google_token' in session:
        google_user_info = google.get('userinfo')
        user = User.query.filter_by(email=google_user_info.data['email']).first()
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
        login_user(user)
        return redirect(url_for('index'))
    return google.authorize(callback=url_for('authorized', _external=True))


@app.route('/google-logout')
def google_logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))


@app.route(app.config['REDIRECT_URI'])
def authorized():
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


## Logout
@app.route('/logout')
def logout():
    '''
    Simply log out the current user.
    '''
    if 'google_token' in session:
        session.pop('google_token', None)
    logout_user()
    return redirect(url_for('index'))

##
## Create User Profile
##

## Create User
@app.route('/create', methods=['GET', 'POST'])
def create():
    '''
    This view creates a new user profile.
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
                user = User(user=form.user.data, password=form.password.data, email=form.email.data, role='user', 
                            first_name=form.first_name.data, last_name=form.last_name.data, unconfirmed_email=form.email.data)
                db.session.add(user)
                db.session.commit()
                send_email_generic(user, user.email, 'activate', 'BrewCalc App Email Confirmation', 'confirm-email.html')
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
    If for some reason the users didn't receive the first confirmation email this view
    allows them to click a button and resend the confirmation message to the registered email.
    It's not possible to change the email address as it is not confirmed.
    '''
    user = current_user
    print(user, user.email)
    send_email_generic(user, user.email, 'activate', 'BrewCalc App New Email Confirmation', 'confirm-email.html')
    print('email sent')
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
    '''
    form = SendEmailResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.isGoogleUser:
                flash('Try to log in with your Google Account!', 'error')
                return redirect(url_for('login'))
            if user.email_confirmed == True:
                # Users can send an email requesting a reset in their password; only confirmed users are able to do this.
                send_email_generic(user, user.email, 'reset_with_token', 'Passoword reset requested', 'reset-password-email.html')
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
    a email confirmation. In any case is necessary to provide the current password in order to save
    changes.
    '''
    # Get current user and pass as object to EditForm or EditFormSocial classes in the instantiation,
    # providing form fields with pre-loaded information about the user.
    user = current_user
    if user.isGoogleUser:
        form = EditFormSocial(obj=user)
        if form.validate_on_submit():
            user.first_name = form.first_name.data
            user.last_name = form.last_name.data
            db.session.commit()
            flash('Saved', 'success')
    else:
        form = EditForm(obj=user)
        if form.validate_on_submit():
            if user.is_password_correct(form.old_password.data):
                # First name and last name will be updated even if not changed
                user.first_name = form.first_name.data
                user.last_name = form.last_name.data
                # If email provided by user in the form is different from email in database,
                # this new email adress will be saved in user.unconfirmed_email and a message
                # will be sent to user in order to confirm this new email address.
                if form.email.data != user.email:
                    # New email address provided couldn't be in use by another user.
                    if User.query.filter_by(email=form.email.data).first() is None:
                        user.unconfirmed_email = form.email.data
                        send_email_generic(user, user.unconfirmed_email, 'email_change', 'Email Change Confirmation', 'confirm-email-change.html')
                        flash('You need to confirm your new email address. A message was sent with instructions.', 'success')
                    else:
                        flash('This email address is already in use by another user. Choose another one.', 'error')
                # Password fields are empty by default and if different of None or empty string set_new_password()
                # method is called with data from form passed as argument (see User Class at models.py)
                if form.new_password.data != '' and form.new_password != None:
                    user.set_new_password(form.new_password.data) # Refer to User class in models.py to see this method implementation.
                db.session.commit()
                flash('Saved', 'success')
            else:
                flash('Incorret password', 'error')
    return render_template('profile.html', form=form, user=user)


## Email Change
@app.route('/email-change/<token>', methods=['GET', 'POST'])
def email_change(token):
    '''
    This view confirms the email change request and stores the old email
    address as an unconfirmed_email in case user wants to revert the change.
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
    send_email_generic(user, user.email, 'unauthorized_email_change', 'Email Change Requested', 'unauthorized-change.html')
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
    '''
    form = DeleteProfileForm()
    user = current_user
    if form.validate_on_submit():
        if user.is_password_correct(form.password.data):
            if user.get_id() == form.user.data:
                if user.get_email() == form.email.data:
                    if form.confirm_delete.data:
                        send_email_generic(user, user.email, 'confirm_delete_user', 'Delete Profile Request', 'delete-profile-email.html')
                        flash('An email was sent to the registered email to confirm profile exclusion.', 'success')                        
                        logout_user()
                        return redirect(url_for('index'))
                    else:
                        flash('Check to confirm profile exclusion', 'error')
                else:
                    flash('Incorrect email address', 'error')
            else:
                flash('Incorrect username', 'error')
        else:
            flash('Incorrect password', 'error')
    return render_template('delete-profile.html', form=form)


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