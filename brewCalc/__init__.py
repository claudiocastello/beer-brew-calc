from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_sendgrid import SendGrid
from flask_oauthlib.client import OAuth
from flask_admin import Admin

app = Flask(__name__)
app.config.from_pyfile('config.py')

# flask-sqlalchemy
db = SQLAlchemy(app)

# flask-bcrypt
bcrypt = Bcrypt(app)

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Insert your username or email to access this page."

# wtforms CSRF protection
csrf = CSRFProtect(app)

# flask-mail
mail = SendGrid(app)

# OAuth
oauth = OAuth(app)

# Flask-Admin
admin = Admin(app, name='brewCalc', template_mode='bootstrap3')

import brewCalc.views