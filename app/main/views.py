from datetime import datetime
from flask import render_template, session, redirect, url_for, flash, request, current_app
from . import main
from .forms import NameForm
from .. import db
from ..models import User
from ..email import send_email


@main.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            db.session.add(user)
            session['known'] = False
            if current_app.config['FLASKY_ADMIN']:
                send_email(current_app.config['FLASKY_ADMIN'], 'New user', 'mail/new_user', user=user)
                flash('Sending a new user email')
        else:
            session['known'] = True
        session['name'] = form.name.data
        form.name.data = ''
        return redirect(url_for('.index'))
    return render_template('index.html',
                           current_time=datetime.utcnow(),
                           form=form,
                           name=session.get('name'),
                           known=session.get('known', False))


@main.route('/user/<name>')
def user(name):
    return render_template('user.html', name=name)


@main.route('/agent')
def agent():
    user_agent = request.headers.get('User-Agent')
    return '<p>Your user agent is %s</p>' % user_agent
