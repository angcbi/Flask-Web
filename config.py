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
    SQLALCHEMY_RECORD_QUERIES = True
    DB_QUERY_TIMEOUT = 0.5
    SLOW_DB_QUERY_TIME = 0.1
    JWT_AUTH_URL_RULE = '/api/v1.1/token'
    JWT_AUTH_URL_OPTIONS = {'methods': ['GET', 'POST']}


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
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URI') or \
            'mysql://web:web@localhost/r'

class UnixDevelopment(Development):
    @classmethod
    def init_app(cls, app):
        Development.init_app(app)

        import logging
        from logging.handlers import SMTPHandler, SysLogHandler
        credentials, secure = None, None
        if getattr(cls, 'MAIL_USERNAME', None) is not None:
            credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
            if getattr(cls, 'MAIL_USE_TLS', None):
                secure = ()

            mail_handler = SMTPHandler(
                mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
                fromaddr=cls.MAIL_SENDER,
                toaddrs=[cls.XYCH_ADMIN],
                subject=cls.MAIL_SUBJECT_PREFIX + ' App Error',
                credentials=credentials,
                secure=secure
            )
            mail_handler.setLevel(logging.ERROR)
            mail_handler.setFormatter(logging.Formatter("""
                Message type: %(levelname)s
                Location:     %(pathname)s:%(lineno)d
                Module:       %(module)s
                Function:     %(funcName)s
                Time:         %(asctime)s
                Message:      %(message)s"""))
            app.logger.addHandler(mail_handler)

            sys_log = SysLogHandler(address='/dev/log')
            sys_log.setLevel(logging.WARNING)
            app.logger.addHandler(sys_log)



class TestingConfig(config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URI') or \
            'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')


class ProductionConfig(config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI') or \
            'sqlite:///' + os.path.join(basedir, 'data.sqlite')

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        import logging
        from loggint.handlers import SMTPHandler
        credentials = None
        secure = None
        
        if getattr(cls, 'MAIL_USERNAME', None) is not None:
            credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
            if getattr(cls, 'MAIL_USE_TLS', None):
                secure = ()

            mail_handler = SMTPHandler(
                mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
                fromaddr=cls.MAIL_SENDER,
                toaddrs=[cls.XYCH_ADMIN],
                subject=cls.MAIL_SUBJECT_PREFIX + ' Application Error',
                credentials=credentials,
                secure=secure
                )
            mail_handler.setLevel(logging.ERROR)
            app.logger.addHandler(mail_handler)

class UnixConfig(ProductionConfig):
    @classmethod
    def init_app(cls, app):
        Production.init_app(app)

        import logging
        from logging.handlers import SysLogHandler
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.WARNING)
        app.logger.addHandler(syslog_handler)



config = {
    'development': Development,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': UnixDevelopment,
}
