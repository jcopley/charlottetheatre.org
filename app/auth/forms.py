from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo, Email
from ..models import User


class LoginForm(FlaskForm):
    email_or_username = StringField('Enter username or email:', validators=[DataRequired(), Length(1, 120)])
    password = PasswordField('Password:', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('Enter email:', validators=[DataRequired(), Length(1, 120)])
    submit = SubmitField('Log In')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Unknown email address.')


class PasswordResetForm(FlaskForm):
    email = StringField('Your email:', validators=[DataRequired(), Length(1, 120)])
    password = PasswordField('New Password:', validators=[DataRequired()])
    password2 = PasswordField('Confirm Password:', validators=[DataRequired(),
                                                       EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Update password')


class PasswordChangeForm(FlaskForm):
    old_password = PasswordField('Old Password:', validators=[DataRequired()])
    password = PasswordField('New Password:', validators=[DataRequired()])
    password2 = PasswordField('Confirm New Password:', validators=[DataRequired(),
                                                       EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Update password')


class RegistrationForm(FlaskForm):
    name = StringField('Your name:', validators=[DataRequired(), Length(1, 100)])
    username = StringField('Username:', validators=[DataRequired(), Length(1, 120)])
    email = StringField('Email:', validators=[DataRequired(), Length(1, 120)])
    password = PasswordField('Password:', validators=[DataRequired()])
    password2 = PasswordField('Password:', validators=[DataRequired(),
                                                       EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already registered')


class ChangeEmailForm(FlaskForm):
    email = StringField('New Email', validators=[DataRequired(), Length(1, 64),
                                                 Email()])

    password = PasswordField('Password', validators=[DataRequired()])

    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')