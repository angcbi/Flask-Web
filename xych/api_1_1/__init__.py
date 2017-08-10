#!/usr/bin/env python
# encoding: utf-8

from flask import Blueprint

api = Blueprint('api_v1.1', __name__)


from . import posts, token
