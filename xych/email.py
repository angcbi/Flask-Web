#!/usr/bin/env python
# coding=utf-8
from threading import Thread

from flask import render_template, current_app 
from flask_mail import Message

from . import mail


def send_sync_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_mail(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    msg = Message(app.config['MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                 sender=app.config['MAIL_SENDER'], recipients=[to])

    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_sync_email, args=(app, msg))
    thr.start()
    return thr
