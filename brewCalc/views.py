## BrewCalc App ##
## Author: Claudio Castello

## Flask Imports ##
from flask import request, abort, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from wtforms import PasswordField

## App Imports ##
from brewCalc import app, db, login_manager
from brewCalc.forms import LoginForm, CreateForm, EditForm, RecoverForm, DeleteProfileForm
from brewCalc.models import User

## Other Imports ##
from functools import wraps

## Required roles function
def required_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapped
    return wrapper

## Login manager
@login_manager.user_loader
def load_user(user):
    return User.query.filter_by(user=user).first()



## Index
@app.route('/', methods=['GET'])
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    return redirect(url_for('login'))


## Login and logout
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(user=form.user.data).first()
        if user and user.is_password_correct(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password', 'error')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


## Create and delete user profile
@app.route('/create', methods=['GET', 'POST'])
def create():
    form = CreateForm()
    if form.validate_on_submit():
        if User.query.filter_by(user=form.user.data).first() is None:
            user = User(user=form.user.data, password=form.password.data, email=form.email.data, role='user', first_name=form.first_name.data, last_name=form.last_name.data)
            db.session.add(user)
            db.session.commit()
            flash('New account created!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already taken. Choose another one.', 'error')
    return render_template('create.html', form=form)


@app.route('/delete-profile', methods=['GET', 'POST'])
@login_required
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


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    form = EditForm(obj=user)
    if form.validate_on_submit():
        if user.is_password_correct(form.old_password.data):
            for field in form:
                if field.data and field.name != 'csrf_token' and field.name != 'new_password' and field.name != 'confirm_new':
                    setattr(user, field.name, field.data)        
            if form.new_password.data != '' and form.new_password != None:
                user.set_new_password(form.new_password.data) # Refer to User class in models.py to see this method implementation.
            db.session.commit()
            flash('Saved', 'success')
        else:
            flash('Incorret password', 'error')
    return render_template('profile.html', form=form)


## Recover user and reset password
@app.route('/recover', methods=['GET', 'POST'])
def recover():
    form = RecoverForm()
    return render_template('recover.html', form=form)


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    pass



## Recipe related views
@app.route('/recipes', methods=['GET'])
@login_required
def recipes():
    return render_template('recipes.html')