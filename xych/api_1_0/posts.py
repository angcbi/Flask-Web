#!/usr/bin/env python
# encoding: utf-8
from flask import jsonify, url_for, request, g, current_app

from . import api
from .authentication import auth
from .decorators import permission_required
from .errors import forbidden
from .. import db
from ..models import Post, Permission, Comment

@api.route('/posts/')
@auth.login_required
def get_posts():
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(page,
                current_app.config['POSTS_PER_PAGE'], error_out=False)
    posts =  pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('api.get_posts', page=page - 1, _external=True)
    next = None
    if pagination.has_next:
        next = url_for('api.get_posts', page=page + 1, _external=True)
    return jsonify({'posts': [post.to_json() for post in posts],
                    'prev': prev,
                    'next': next,
                    'count': pagination.total})


@api.route('/posts/<int:id>')
@auth.login_required
def get_post(id):
    post = Post.query.get_or_404(id)
    return jsonify(post.to_json())

@api.route('/posts/', methods=['POST'])
@permission_required(Permission.WRITE_ARTICLES)
def new_post():
    post = Post.from_json(request.json)
    post.author = g.current_user
    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_json()), 201, {'Location': url_for('api.get_post', id=post.id, _external=True)}

@api.route('/posts/<int:id>', methods=['PUT'])
@permission_required(Permission.WRITE_ARTICLES)
def edit_post(id):
    post = Post.query.get_or_404(id)
    if g.current_user != post.author and \
            not g.current_user.can(Permission.ADMINISTER):
        return forbidden('Insufficient permissions')
    post.body = request.json.get('body', post.body)
    db.session.add(post)
    return jsonify(post.to_json())

@api.route('/posts/<int:id>/comments')
@auth.login_required
def get_post_comments(id):
    post = Post.query.get_or_404(id)
    page = request.args.get('page', 1, type=int)
    pagination = post.comments.order_by(Comment.timestamp.desc()).paginate(page,
            current_app.config['COMMENTS_PER_PAGE'], error_out=False)
    comments = pagination.items
    prev, next = None, None
    if pagination.has_prev:
        prev = url_for('api.get_post_comments', id=id, page=page - 1, _external=True)
    if pagination.has_next:
        next = url_for('api.get_post_comments', id=id, page=page + 1, _external=True)
    return jsonify({'comments': [comment.to_json() for comment in comments],
                    'prev': prev,
                    'next': next,
                    'count': pagination.total})

@api.route('/posts/<int:id>/comments', methods=['POST'])
@auth.login_required
@permission_required(Permission.COMMENT)
def new_posts_comments(id):
    post = Post.query.get_or_404(id)
    comment = Comment.from_json(request.json)
    comment.author = g.current_user
    comment.post = post
    db.sesion.add(comment)
    db.session.commit()
    return jsonify(comment.to_json()), 201, {'Location': url_for('api.get_comment', id=comment.id, _externale=True)}
