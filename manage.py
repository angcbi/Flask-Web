#!/usr/bin/env python
# coding=utf-8
import os

from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from flask_jwt import JWT

from xych import create_app, db
from xych.models import User, Role, Post, authenticate, identity


app = create_app(os.getenv('APP_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)
jwt = JWT(app, authenticate, identity)

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

@manager.option('-d', '--dir', dest='profile_dir')
def profile(length=25, profile_dir=None):
    """Start the application under the code profiler."""
    from werkzeug.contrib.profiler import ProfilerMiddleware
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[length],
                    profile_dir=profile_dir)
    app.run()

@manager.command
def deploy():
    """Run deployment tasks"""
    from flask_migrate import upgrade
    from xych.models import User, Role

    upgrade()
    
    Role.insert_roles()
    User.add_self_follows()

    


if __name__ == '__main__':
    manager.run()

