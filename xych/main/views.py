#!/usr/bin/env python
# coding=utf-8
from datetime import datetime

from flask import (render_template, session,
                   redirect, url_for, flash, abort,
                   request, current_app)
from flask_login import login_required, current_user

from . import main
from .forms import NameForm, EditProfileForm, EditProfileAdminForm, PostForm
from .. import db
from ..models import User, Role, Permission, Post
from ..email import send_mail
from ..decorators import admin_required, permission_required

@main.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        form.body.data = None
        return redirect(url_for('.index'))

    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(
                page, per_page=current_app.config['POSTS_PER_PAGE'],
                error_out=False)
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts, pagination=pagination)

@main.route('/user/<username>/')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    return render_template('user.html', user=user, posts=posts)


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
       flash(u'个人资料已更新')
       return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)

@main.route('/post/<int:id>')
def post(id):
    post = Post.query.get_or_404(id)
    return render_template('post.html', posts=[post])

@main.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and not current_user.can(Permission.ADMINISTAER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash(u'编辑成功')
        return redirect(url_for('.post', id=post.id))

    form.body.data = post.body
    return render_template('edit_post.html', form=form)

@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.queyr.filter_by(username=username).frist()
    if user is None:
        flash(u'无效用户')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash(u'你已关注该用户')
        return redirect(url_for('.index'))
    current_user.follow(user)
    flash(u'你正在关注 %s' % username)
    return redirect(url_for('.user', username=username))

@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(u'无效用户')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(page,
        per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    follows = [{'user': item.user, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title=u'我的关注着',
                           endpoint='.followers', pagination=pagination,
                           follows=follows)

