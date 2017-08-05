# -*- coding:utf-8 -*-
from datetime import datetime


from . import db

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    pub_date = db.Column(db.DateTime, default=datetime.utcnow)
    course_id = db.Column(db.Integer, db.ForeignKey('couses.id'))

    def __repr__(self):
        return '<Student %r>' % self.name

class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    students = db.relationship(Student, backref='course', lazy='dynamic')

    def __repr__(self):
        return '<Student %r>' % self.name
