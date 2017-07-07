from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, DateField
from wtforms.validators import DataRequired, Email, Optional, Length
from wtforms.fields.html5 import EmailField
from brewCalc.models import FIELD_MAX_LIM

class LoginForm(FlaskForm):
    user = StringField('User', validators=[DataRequired(message='Insert your username')], description={'placeholder': 'Username'})
    password = PasswordField('Password', validators=[DataRequired(message='Insert your password')], description={'placeholder': 'Password'})
    remember_me = BooleanField('Remember', default=False)


class CreateForm(FlaskForm):
    user = StringField('User', validators=[DataRequired(message='Insert desired username')], description={'placeholder': 'Desired username'})
    password1 = PasswordField('Password1', validators=[DataRequired(message='Insert desired password')], description={'placeholder': 'Desired password'})
    password2 = PasswordField('Password2', validators=[DataRequired(message='Repeat password')], description={'placeholder': 'Repeat password'})
    email = StringField('Email', validators=[DataRequired(message='Insert your email')], description={'placeholder': 'Email'})
    first_name = StringField('First Name', validators=[DataRequired(message='Insert your first name')], description={'placeholder': 'First name'})
    last_name = StringField('Last Name', validators=[DataRequired(message='Insert your last name')], description={'placeholder': 'Last name'})


class RecoverForm(FlaskForm):
    user = StringField('User', validators=[DataRequired(message='Insert desired username')], description={'placeholder': 'Desired username'})
    email = StringField('Email', validators=[DataRequired(message='Insert your email')], description={'placeholder': 'Email'})