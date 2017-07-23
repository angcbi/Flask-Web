#!/usr/bin/env python
# coding=utf-8
from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, current_user, logout_user

from . import auth
from .forms import LoginForm, RegisterForm
from .. import db
from ..models import User
from ..email import send_mail



@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))

        flash(u'无效的账号或密码')

    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash(u'你已退出')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_mail(user.email, '确认你的账号',
                  'auth/email/confirm', user=user, token=token)
        flash(u'一份确认邮件已发送到您的邮箱，请查收.<a href="http://mail.{}">立即登录</a>'.format(user.email.split('@')[-1]))
        return redirect(url_for('.login'))

    return render_template('auth/register.html', form=form)

