#!/usr/bin/env python
# encoding: utf-8

import re
import json
import base64

import jwt
from flask import current_app


def create_token(payload, alg='HS256'):
    SECRET_KEY = current_app.config.get('SECRET_KEY') or 'IJSOWC1U9NAF0NT'
    # 不传公共声明，payload不会自动添加公共声明
    # iat 时间需要为时间戳， 不要转换成13位整形(毫秒级)
    # jwt decode 会判断iat时间，exp时间
    #payload.update({
    #    'identity': user_id,
    #    'iat': now,
    #    'nbf': now,
    #    'exp': now + 60 * 60,
    #})
    return jwt.encode(payload, SECRET_KEY, algorithm=alg)

def parse_token(token):
    SECRET_KEY = current_app.config.get('SECRET_KEY') or 'IJSOWC1U9NAF0NT'
    try:
        if token.lower().startswith('jwt'):
            _, data = re.split(r'\s+', token)
            header, _, _ = data.split('.')
            alg = json.loads(base64.b64decode(header)).get('alg')

            # JWT decode 会自动判断payload中过期时间
            return jwt.decode(data, SECRET_KEY, algorithms=[alg])
    except Exception, e:
        print e
        current_app.logger.exception(e)

