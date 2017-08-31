#!/usr/bin/env python
# coding=utf-8
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_pagedown import PageDown
from flask_oauthlib.client import OAuth
from flask_oauthlib.provider import OAuth2Provider


from config import config


bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
loginmanager = LoginManager()
loginmanager.session_protection = 'strong'
loginmanager.login_view = 'auth.login'
loginmanager.login_message = u'请先登录'
pagedown = PageDown()
oauth = OAuth()
weibo = oauth.remote_app(
    'weibo',
    app_key='WEIBO'
)
oauth2server = OAuth2Provider()

def change_weibo_header(uri, headers, body):
    auth = headers.get('Authorization')
    if auth:
        auth = auth.replace('Bearer', 'OAuth2')
        headers['Authorization'] = auth
    return uri, headers, body

weibo.pre_request = change_weibo_header

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    loginmanager.init_app(app)
    pagedown.init_app(app)
    oauth.init_app(app)
    oauth2server.init_app(app)

    from .main import main as main_blueprint
    from .auth import auth as auth_blueprint
    from .api_1_0 import api as api_1_0_blueprint
    from .api_1_1 import api as api_1_1_blueprint
    from .oauth2 import oauth2 as oauth2_blueprint

    app.register_blueprint(main_blueprint)
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    app.register_blueprint(api_1_0_blueprint, url_prefix='/api/v1.0')
    app.register_blueprint(api_1_1_blueprint, url_prefix='/api/v1.1')
    app.register_blueprint(oauth2_blueprint, url_prefix='/oauth2')

    return app

