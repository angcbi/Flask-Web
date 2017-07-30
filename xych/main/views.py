#!/usr/bin/env python
# coding=utf-8
from datetime import datetime

from flask import (render_template, session,
                   redirect, url_for, flash, abort)
from flask_login import login_required, current_user

from . import main
from .forms import NameForm, EditProfileForm, EditProfileAdminForm
from .. import db
from ..models import User, Role
from ..email import send_mail
from ..decorators import admin_required

@main.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            session['known'] = False
            db.session.add(user)

            send_mail(user.username, '感谢您注册',
                      'mail/new_user', user=user)
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

@main.route('/user/<username>/')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)

    return render_template('user.html', user=user)


@main.route('/edit-profile/', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm() 
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash(u'个人信息已更改')
        return redirect(url_for('.user', username=current_user.username))

    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)

@main.route('/edit-profil/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
       user.email = form.email.data
       user.username = form.username.data
       user.confirmed = form.confirmed.data
       user.role = Role.query.get(form.role.data)
       user.name = form.name.data
       user.location = form.location.data
       user.about_me = form.about_me.data
       db.session.add(user)
       flash('The profile has been updated.')
       return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user) 
