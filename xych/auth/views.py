#!/usr/bin/env python
# coding=utf-8
import requests
from flask import render_template, redirect, url_for, request, flash, session, jsonify, g
from flask_login import login_user, login_required, current_user, logout_user

from . import auth
from .forms import LoginForm, RegisterForm, ModifyPasswordForm, ResetPasswordForm, ResetForm
from .. import db, weibo
from ..models import User, Permission, OAuthClient
from ..email import send_mail
from ..decorators import admin_required, permission_required



@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            print g.oauth
            if getattr(g, 'oauth', None) is not None:
                print g.oauth
                uuid, source = g.oauth
                oauth_client = OAuthClient(uuid=uuid, source=source, user=user)
                db.session.add(oauth_client)
            return redirect(request.args.get('next') or url_for('main.index'))

        flash(u'无效的账号或密码')

    auth = request.args.get('auth', 0, type=int)
    return render_template('auth/login.html', form=form, auth=auth)

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
        if getattr(g, 'oauth', None) is not None:
            uuid, source = g.oauth
            oauth_client = OAuthClient(uuid=uuid, source=source, user=user)
            db.session.add(oauth_client)
        token = user.generate_confirmation_token()
        send_mail(user.email, '确认你的账号',
                  'auth/email/confirm', user=user, token=token)
        flash(u'一份确认邮件已发送到您的邮箱，请查收.'.format(user.email.split('@')[-1]))
        return redirect(url_for('.login'))

    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))

    if current_user.confirm(token):
        flash(u'你已经确认你的账号')
    else:
        flash(u'确认链接无效或者过期')

    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    # 检查是否有weibo的授权session存在，存在获取uid,保存到g.oauth中，access_token过期，删除session
    if 'weibo_oauth' in session:
        access_token = session['weibo_oauth'][0]
        resp = weibo.get('/2/account/get_uid.json' + '?access_token=' + access_token)
        if resp.status == requests.codes.ok and 'error_code' not in resp.data:
            g.oauth = (resp.data['uid'], 'weibo')
        else:
            session.pop('weibo_oauth')

    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
       and request.endpoint[:5] != 'auth.' \
       and request.endpoint != 'status':
            return redirect(url_for('auth.unconfirmed'))

@login_required
@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html', email_site='https://mail.' + current_user.email.split('@')[-1])


@auth.route('/confirm')
@login_required
def resend_confirmed():
    token = current_user.generate_confirmation_token()
    send_mail(current_user.email, '确认你的账号', 'auth/email/confirm',
             user=current_user, token=token)
    flash(u'一份确认邮件已发送到您的邮箱')
    return redirect(url_for('main.index'))


@auth.route('/ModifyPasswordForm', methods=['GET', 'POST'])
@login_required
def modify_password():
    form = ModifyPasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            current_user.password = form.password1.data
            db.session.add(current_user)
            flash(u'修改密码成功,跳转到登录页面')
            return redirect(url_for('.logout'))
        else:
            flash(u'原密码错误')

    return render_template('auth/modify_password.html', form=form)

@auth.route('/ResetPasswordForm', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            token = user.generate_confirmation_token()
            send_mail(form.email.data, '重置密码', 'auth/email/reset',\
                      token=token, user=user, message=u'重置密码')
            flash(u'一封重置密码的邮件已发送')
            return render_template('auth/reset_password1.html', \
                               email_site='http://mail.' + form.email.data.split('@')[-1])
        else:
            flash(u'账号不存在')

    return render_template('auth/reset_password.html', form=form)

@auth.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    form = ResetForm()
    if form.validate_on_submit():
        data = User.parse(token)
        print data, '*'*50
        if data:
            user = User.query.get(data.get('confirm'))
            if user is not None:
                user.password = form.password.data
                db.session.add(user)
                flash(u'重置密码成功')
                return redirect(url_for('auth.login'))
            else:
                flash(u'用户不存在')

        else:
            flash(u'链接已失效')
    return render_template('auth/reset.html', form=form)


@auth.route('/changeEmail/', methods=['GET', 'POST'])
@login_required
def change_email():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if not User.query.filter_by(email=form.email.data).first():
            token = current_user.generate_confirmation_token(ext=form.email.data)
            send_mail(form.email.data, '更换邮箱', 'auth/email/change',
                     token=token, user=current_user, message=u'更换邮箱')
            return render_template('auth/change_email1.html', email_site='http://mail.' + form.email.data.split('@')[-1])
        else:
            flash(u'邮箱已存在')

    return render_template('auth/change_email.html', form=form)


@auth.route('/change/<token>')
def change(token):
    data = User.parse(token)
    user = User.query.get(data['confirm'])
    new_email = data.get('ext')
    if user and new_email:
        user.change_email(new_email)
        db.session.add(user)
        flash(u'修改邮箱成功')
        return redirect(url_for('auth.login'))

    flash(u'链接失效')
    return render_template('auth/change.html')



@auth.route('/admin')
@login_required
@admin_required
def for_admin():
    return 'for administrator'


@auth.route('/moderator')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def for_moderators_only():
    return 'for moder'


@auth.route('/weibo_login')
def weibo_login():
    if 'weibo_oauth' in session:
            uid, source = g.oauth
            print session, g.oauth
            oauth_relation = OAuthClient.query.filter_by(uuid=uid, source='weibo').first()
            if oauth_relation is None:
                return redirect(url_for('.login', auth=1))

            user = oauth_relation.user
            login_user(user)
            flash(u'登录成功')
            return redirect(url_for('main.index'))
    # next_url = request.args.get('next') or request.referrer or None
    return weibo.authorize(
        callback=url_for('.authorized',  _external=True)
    )

@auth.route('/authorized')
def authorized():
    resp = weibo.authorized_response()
    if resp is None:
        return 'Access deny: reason=%s, error=%s' %(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['weibo_oauth'] = (resp['access_token'], '')
    g.oauth = (resp['uid'], 'weibo')
    print g.oauth
    return redirect(url_for('.weibo_login'))
    # return jsonify(resp)

@weibo.tokengetter
def get_oauth_token():
    return session.get('weibo_oauth')

