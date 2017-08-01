#!/usr/bin/env python
# coding=utf-8
import os

from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

from xych import create_app, db
from xych.models import User, Role, Post


app = create_app(os.getenv('APP_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)

def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role, Post=Post)
manager.add_command('shell', Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


@manager.command
def test():
    """运行单元测试"""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)


if __name__ == '__main__':
    manager.run()

