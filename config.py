#!/usr/bin/env python
# coding=utf-8
import os
basedir = os.path.dirname(os.path.abspath(__file__))

class config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'IOS3D-BLIE3R-CLDO!-'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    MAIL_SUBJECT_PREFIX = '[星宇晨辉] '
    MAIL_SENDER = '星宇晨辉管理员<vip_susan@sina.cn>'
    XYCH_ADMIN = '1371998102@qq.com'
    POSTS_PER_PAGE = 20
    COMMENTS_PER_PAGE = 20


    @staticmethod
    def init_app(app):
        pass


class Development(config):
    DEBUG = True
    MAIL_SERVER = 'smtp.sina.cn'
    MAIL_PORT = 25
    MAIL_USER_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'vip_susan@sina.cn'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'VIP_SUSAN'
    # SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URI') or \
    #         'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URI') or \
            'mysql://web:web@localhost/r'

class UnixDevelopment(Development):
    @classmethod
    def init_app(cls, app):
        Development.init_app(app)

        import logging
        from logging.handlers import SMTPHandler
        credentials, secure = None, None
        if getattr(cls, 'MAIL_USERNAME', None) is not None:
            credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
            if getattr(cls, 'MAIL_USE_TLS', None):
                secure = ()

            mail_handler = SMTPHandler(
                mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
                fromaddr=cls.MAIL_SENDER,
                toaddrs=['vip_susan@sina.cn'],
                subject=cls.MAIL_SUBJECT_PREFIX + ' App Error',
                credentials=credentials,
                secure=secure
            )
            # mail_handler.setLevel(logging.ERROR)
            mail_handler.setLevel(logging.DEBUG)
            app.logger.addHandler(mail_handler)


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

    'default': UnixDevelopment,
}
