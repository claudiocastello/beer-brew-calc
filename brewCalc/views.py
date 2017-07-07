from flask import request, abort, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from wtforms import PasswordField

from brewCalc import app, db, login_manager
from brewCalc.forms import LoginForm, CreateForm, RecoverForm
from brewCalc.models import User

from functools import wraps

def required_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapped
    return wrapper


@login_manager.user_loader
def load_user(user):
    return User.query.filter_by(user=user).first()


@app.route('/', methods=['GET'])
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    return redirect(url_for('login'))


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


@app.route('/create', methods=['GET', 'POST'])
def create():
    form = CreateForm()
    return render_template('create.html', form=form)


@app.route('/recover', methods=['GET', 'POST'])
def recover():
    form = RecoverForm()
    return render_template('recover.html', form=form)


@app.route('/profile', methods=['GET'])
def profile():
    return render_template('profile.html')


@app.route('/recipes', methods=['GET'])
def recipes():
    return render_template('recipes.html')