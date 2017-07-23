#!/usr/bin/env python
# coding=utf-8
from datetime import datetime

from flask import (render_template, session,
                   redirect, url_for)

from . import main
from .forms import NameForm
from .. import db
from ..models import User

@main.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            session['known'] = False
            db.session.add(user)

            send_mail(username, '感谢您注册',
                      'main/new_user', user=user)
        else:
            session['known'] = True

        session['name'] = user.username
        form.name.data = ''

        redirect(url_for('.index'))
    
    res = {
        'name': session.get('name'),
        'form': form,
        'knownn': session.get('know'),
        'current_time': datetime.utcnow(),
    }

    return render_template('index.html', **res)
