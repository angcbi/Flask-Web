#!/usr/bin/env python
# coding=utf-8
from flask_wtf import FlaskForm 
# from flask_wtf.file import FileAllowed, FileRequired, FileField
from wtforms import StringField, SubmitField, DateField
from wtforms.validators import DataRequired


class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    # file = FileField(u'文件', validators=[FileRequired(),]) 
    submit = SubmitField('Submit')
