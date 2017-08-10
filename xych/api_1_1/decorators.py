#!/usr/bin/env python
# encoding: utf-8
import time
from functools import wraps

from flask import g, request

from .auth import parse_token
from ..api_1_0.errors import unauthorized
from ..models import User


def c_jwt_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get('Authorization'):
            token = request.headers['Authorization']
            payload = parse_token(token)
            if payload is not None:
                g.c_current_user = User.identity(payload)
                return f(*args, **kwargs)

        return unauthorized('Unauthorized')
    return wrapper
