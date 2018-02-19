from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, PasswordResetRequestForm, \
                    PasswordResetForm, PasswordChangeForm, ChangeEmailForm


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
            and request.endpoint[:5] != 'auth.':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter((User.email == form.email_or_username.data) | (User.username == form.email_or_username.data)).first()
        # user = User.query.filter_by(email=form.email_or_username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid login information.')
    return render_template('auth/login.html', form=form)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(name=form.name.data,
                    username=form.username.data,
                    email=form.email.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Please Confirm Your Account', 'auth/mail/confirm', user=user, token=token)
        flash('You can now log in.')
        return redirect(url_for('.login'))
    return render_template('auth/template.html', form=form, title='Register')


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('Your account is confirmed.')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/new-email/<token>')
@login_required
def new_email(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('Your account is confirmed.')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Please Confirm Your Account', 'auth/mail/confirm', user=current_user, token=token)
    flash('A confirmation email has been sent to %s.' % (current_user.email))
    return redirect(url_for('main.index'))


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def send_email_confirm():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            token = current_user.generate_email_change_token(form.email.data)
            send_email(form.email.data, 'Confirm Your New Email', 'auth/mail/confirm_email', token=token)
            flash('Instructions for confirming your new email have been sent to %s.' % (form.email.data))
            return redirect(url_for('main.index'))
        flash('Email not found.')
    return render_template('auth/template.html', form=form, title='change Your Email')


@auth.route('/send-reset', methods=['GET', 'POST'])
def send_password_reset():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            token = user.generate_reset_token()
            send_email(form.email.data, 'Reset Your Password', 'auth/mail/reset_password', token=token)
            flash('A password reset email has been sent to %s.' % (form.email.data))
            return redirect(url_for('auth.login'))
        flash('Email not found.')
    return render_template('auth/template.html', form=form, title='Reset Your Password')


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            user.reset_password(token, form.password.data)
            login_user(user)
            flash('Your password has been reset')
            return redirect(url_for('main.index'))
        flash('Email not found.')
    return render_template('auth/template.html', form=form, title='Reset Your Password')


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            flash('Your password has been updated')
            return redirect(url_for('main.index'))
        flash('Invalid old password.')
    return render_template('auth/template.html', form=form, title='Change Your Password')


@auth.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))
