#!/usr/bin/env python
# coding=utf-8
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_pagedown import PageDown

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

    from .main import main as main_blueprint
    from .auth import auth as auth_blueprint
    from .api_1_0 import api as api_1_0_blueprint
    app.register_blueprint(main_blueprint)
    app.register_blueprint(auth_blueprint, url_prefix='/auth/')
    app.register_blueprint(api_1_0_blueprint, url_prefix='/api/v1.0')

    return app

