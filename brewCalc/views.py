## BrewCalc App ##
## Author: Claudio Castello

## Flask Imports ##
from flask import request, abort, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from wtforms import PasswordField

## App Imports ##
from . import app, db, login_manager
from .forms import LoginForm, CreateForm, EditForm, SendEmailResetForm, ResendConfirmForm, ResetPasswordForm, DeleteProfileForm
from .models import User
from .utils import required_roles, load_user, send_confirm_email, confirmed_email, check_confirmed, send_reset_email, send_change_email


##
## Index
##
@app.route('/', methods=['GET'])
@login_required
@check_confirmed
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    return redirect(url_for('login'))

##
## Login and logout
##

## Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        if '@' in form.user.data:
            user = User.query.filter_by(email=form.user.data).first()
        else:
            user = User.query.filter_by(user=form.user.data).first()

        if user and user.is_password_correct(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect(url_for('index'))
        else:
            flash('Incorrect username/email or password', 'error')
    return render_template('login.html', form=form)

## Logout
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

##
## Create User Profile
##

## Create User
@app.route('/create', methods=['GET', 'POST'])
def create():
    form = CreateForm()
    if form.validate_on_submit():
        if User.query.filter_by(user=form.user.data).first() is None:
            if User.query.filter_by(email=form.email.data).first() is None:
                user = User(user=form.user.data, password=form.password.data, email=form.email.data, role='user', 
                            first_name=form.first_name.data, last_name=form.last_name.data, unconfirmed_email=form.email.data)
                db.session.add(user)
                db.session.commit()
                send_confirm_email(user)
                flash('New account created! You will receive a confirmation email.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Email address already in our database. Please use another email to proceed.', 'error')
        else:
            flash('Username already taken. Choose another one.', 'error')
    return render_template('create.html', form=form)

## Confirm New User
@app.route('/activate/<token>', methods=['GET', 'POST'])
def activate(token):
    email = confirmed_email(token)
    user = User.query.filter_by(email=email).first_or_404()
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
    user = current_user
    form = ResendConfirmForm()
    return render_template('user_unconfirmed.html', form=form, user=user)


## Resend Confirmation Email
@app.route('/resend-confirmation', methods=['GET', 'POST'])
@login_required
def resend_confirmation():
    user = current_user
    send_confirm_email(user)
    flash('You will receive a new confirmation email.', 'success')
    return redirect(url_for('logout'))
    


##
## Reset password
##

## Send Request for Password Reset
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    form = SendEmailResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.email_confirmed == True:
                send_reset_email(user)
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
    email = confirmed_email(token)
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first_or_404()
        user.set_new_password(form.new_password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset-new-password.html', form=form)



##
## User Profile / Edit Profile / Delete Profile
##

## Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@check_confirmed
def profile():
    user = current_user
    form = EditForm(obj=user)
    if form.validate_on_submit():
        if user.is_password_correct(form.old_password.data):
            user.first_name = form.first_name.data
            user.last_name = form.last_name.data
            if form.email.data != user.email:
                if User.query.filter_by(email=form.email.data).first() is None:
                    user.unconfirmed_email = form.email.data
                    send_change_email(user)
                    flash('You need to confirm your new email address. A message was sent with instructions.')
                else:
                    flash('This email address is already in use by another user. Choose another one.', 'error')
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
    email = confirmed_email(token)
    user = User.query.filter_by(email=email).first_or_404()
    user.email = email
    user.unconfirmed_email = None
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('login'))


## Delete Profile
@app.route('/delete-profile', methods=['GET', 'POST'])
@login_required
@check_confirmed
def delete_profile():
    form = DeleteProfileForm()
    user = current_user
    if form.validate_on_submit():
        if user.is_password_correct(form.password.data):
            if user.get_id() == form.user.data:
                if user.get_email() == form.email.data:
                    if form.confirm_delete.data:
                        db.session.delete(user)
                        db.session.commit()
                        flash('Profile Deleted', 'success')
                        logout_user()
                        return redirect(url_for('index'))
                    else:
                        flash('Check to confirm profile exclusion', 'error')
                else:
                    flash('Incorrect email adress', 'error')
            else:
                flash('Incorrect username', 'error')
        else:
            flash('Incorrect password', 'error')
    return render_template('delete-profile.html', form=form)



#####################################################################################################################################

## Recipe related views
@app.route('/recipes', methods=['GET'])
@login_required
@check_confirmed
def recipes():
    return render_template('recipes.html')