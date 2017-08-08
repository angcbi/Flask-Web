#!/usr/bin/env python
# encoding: utf-8

from flask import jsonify

from . import api
from ..exceptions import ValidationError


def bad_request(message):
    resp = jsonify({'error': 'bad_request', 'message': message})
    resp.status_code = 400
    return resp

def unauthorized(message):
    resp = jsonify({'error': 'unauthorized', 'message': message})
    resp.status_code = 401
    return resp

def forbidden(message):
    resp = jsonify({'error': 'forbidden', 'message': message})
    resp.status_code = 403
    return resp

def method_not_allowed(message):
    resp = jsonify({'error': 'method not allowed', 'message': message})
    resp.status_code = 405
    return resp

@api.errorhandler(ValidationError)
def validation_error(e):
    return bad_request(e.args[0])
