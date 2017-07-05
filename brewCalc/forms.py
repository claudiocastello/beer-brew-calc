from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, DateField
from wtforms.validators import DataRequired, Email, Optional, Length
from wtforms.fields.html5 import EmailField
from turnos.models import FIELD_MAX_LIM
