#!/usr/bin/env python
# encoding: utf-8

from flask import jsonify


def forbidden(message):
    resp = jsonify({'error': 'forbidden', 'message': message})
    resp.status_code = 403
    return resp

def unauthorized(message):
    resp = jsonify({'error': 'unauthorized', 'message': message})
    resp.status_code = 401
    return resp

