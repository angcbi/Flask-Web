#!/usr/bin/env python
# coding=utf-8
import os
basedir = os.path.dirname(os.path.abspath(__file__))

class config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'IOS3D-BLIE3R-CLDO!-'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    MAIL_SUBJECT_PREFIX = '[星宇晨辉] '
    MAIL_SENDER = '星宇晨辉管理员<faladihuan@qq.com>'


    @staticmethod
    def init_app(app):
        pass
    

class Development(config):
    DEBUG = True
    MAIL_SERVER = 'smtp.qq.com',
    MAIL_PORT = 465
    MAIL_USER_SSL = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'faladihuan@qq.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'lhpgaocvrtcofeii'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URI') or \
            'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')


class TestingConfig(config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URI') or \
            'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')


class ProductionConfig(config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI') or \
            'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': Development,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': Development,
}
