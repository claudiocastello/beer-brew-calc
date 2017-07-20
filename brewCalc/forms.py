from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, DateField
from wtforms.validators import DataRequired, EqualTo, Email, Optional, Length
from wtforms.fields.html5 import EmailField

from .models import FIELD_MAX_LIM


# User related forms:
class LoginForm(FlaskForm):
    user = StringField('User', validators=[DataRequired(message='Insert your username')], description={'placeholder': 'Username or email'})
    password = PasswordField('Password', description={'placeholder': 'Password'})
    remember_me = BooleanField('Remember', default=False)


class CreateForm(FlaskForm):
    user = StringField('User', validators=[DataRequired(message='Insert desired username'), Length(max=(FIELD_MAX_LIM['user']))], description={'placeholder': 'Desired username'})
    password = PasswordField('Password', validators=[DataRequired(message='Insert password'), EqualTo('confirm', message='Passwords must match'), Length(min=4, max=(FIELD_MAX_LIM['password']))],description={'placeholder': 'Desired password'})
    confirm = PasswordField('confirm', validators=[DataRequired(message='Repeat password')], description={'placeholder': 'Repeat password'})
    email = StringField('Email', validators=[DataRequired(message='Insert your email'), Email(message='Invalid email address format.'), Length(max=(FIELD_MAX_LIM['email']))], description={'placeholder': 'Email'})
    first_name = StringField('First Name', validators=[DataRequired(message='Insert your first name'), Length(max=(FIELD_MAX_LIM['first_name']))], description={'placeholder': 'First name'})
    last_name = StringField('Last Name', validators=[DataRequired(message='Insert your last name'), Length(max=(FIELD_MAX_LIM['last_name']))], description={'placeholder': 'Last name'})

class ResendConfirmForm(FlaskForm):
    pass

class DeleteProfileForm(FlaskForm):
    user = StringField('User', validators=[DataRequired(message='Insert your username')], description={'placeholder': 'Username'})
    password = PasswordField('Password', validators=[DataRequired(message='Insert your password')], description={'placeholder': 'Password'})
    email = StringField('Email', validators=[DataRequired(message='Insert your email'), Email(message='Invalid email address format.')], description={'placeholder': 'Email'})
    confirm_delete = BooleanField('Check to confirm profile exclusion', default=False)
 

class SendEmailResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message='Insert your email')], description={'placeholder': 'Email'})


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[EqualTo('confirm_new', message='Passwords must match'), Length(min=4, max=(FIELD_MAX_LIM['password'])), Optional()],description={'placeholder': 'New password'})
    confirm_new = PasswordField('confirm_new', description={'placeholder': 'Repeat password'})


class EditForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(message='First name can not be blank'), Length(max=(FIELD_MAX_LIM['first_name']))], description={'placeholder': 'First name'})
    last_name = StringField('Last Name', validators=[DataRequired(message='Last name can not be blank'), Length(max=(FIELD_MAX_LIM['last_name']))], description={'placeholder': 'Last name'})
    email = StringField('Email', validators=[DataRequired(message='Email can not be blank'), Email(message='Invalid email address format.'), Length(max=(FIELD_MAX_LIM['email']))], description={'placeholder': 'Email'})
    old_password = PasswordField('Old Password', validators=[DataRequired(message='Insert password to save changes'), Length(min=4, max=(FIELD_MAX_LIM['password']))], description={'placeholder': 'Old password'})
    new_password = PasswordField('New Password', validators=[EqualTo('confirm_new', message='Passwords must match'), Length(min=4, max=(FIELD_MAX_LIM['password'])), Optional()],description={'placeholder': 'New password'})
    confirm_new = PasswordField('confirm_new', description={'placeholder': 'Repeat password'})


# Recipe related forms: