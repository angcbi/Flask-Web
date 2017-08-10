#!/usr/bin/env python
# encoding: utf-8

from flask import request, g

from . import api
from .decorators import c_jwt_required


@api.route('/protected', methods=['GET', 'POST'])
@c_jwt_required
def protected():
    print 'json', request.json, type(request.json)
    print '*' * 50
    print 'get_data', request.get_data(), type(request.get_data())
    print '*' * 50
    print 'get_json', request.get_json(), type(request.get_json())
    print '*' * 50
    print 'form', request.form, type(request.form)
    print '*' * 50
    print 'data', request.data, type(request.data)
    return '%s' % g.c_current_user
