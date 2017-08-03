#!/usr/bin/env python
# coding=utf-8
from flask import render_template, jsonify, request

from . import main

@main.app_errorhandler(404)
def page_not_found(e):
    if request.accept_mimetypes.accept_json and \
            not request.accept_mimetypes.accept_html:
        resp = jsonify({'error': 'not found'})
        resp.status_code = 404
        return resp
    return render_template('error/404.html'), 404

@main.app_errorhandler(500)
def internal_server_error(e):
    if request.accept_mimetypes.accept_json and \
            not request.accept_mimetypes.accept_html:
        resp = jsonify({'error': 'internal error'})
        resp.status_code = 500
        return resp
    return render_template('error/500.html'), 500


@main.app_errorhandler(403)
def forbidden(e):
    return render_template('error/403.html'), 403
