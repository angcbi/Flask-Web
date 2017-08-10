#!/usr/bin/env python
# encoding: utf-8

import datetime

from flask import request, jsonify, g

from . import api
from .auth import create_token, parse_token
from .decorators import c_jwt_required
from ..api_1_0.errors import bad_request
from ..models import User


@api.route('/get_token', methods=['POST', 'GET'])
def get_token():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return bad_request('Bad Request')

    user = User.authenticate(username, password)
    if user is not None:
        ret = {
            'access_token': create_token({'identity': user.id,
                                            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}),
            'refresh_token': create_token({'identity': user.id,
                                            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)}),
            'expires_in':  60 * 60
        }
        return jsonify(ret)

    return bad_request('Bad request')


@api.route('/refresh_token', methods=['POST', 'GET'])
@c_jwt_required
def refresh_token():
    data = request.get_json() or {}
    refresh_token = data.get('refresh_token')
    payload = parse_token('JWT ' + refresh_token)
    if payload and payload['identity'] == g.current_user.id:
        ret = {
            'access_token': create_token({'identity': g.c_current_user.id,
                                            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}),
            'refresh_token': refresh_token,
            'expires_in':  60 * 60
        }
        return jsonify(ret)
    return bad_request('Bad request')


