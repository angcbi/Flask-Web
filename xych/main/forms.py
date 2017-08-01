#!/usr/bin/env python
# coding=utf-8
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, Regexp
from wtforms import ValidationError

from ..models import Role, User


class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    # file = FileField(u'文件', validators=[FileRequired(),])
    submit = SubmitField('Submit')


class EditProfileForm(FlaskForm):
    name = StringField(u'真实姓名', validators=[Length(0, 64)])
    location = StringField(u'地区', validators=[Length(0,64)])
    about_me = TextAreaField(u'个人简介')
    submit = SubmitField(u'修改')


class EditProfileAdminForm(FlaskForm):
    email = StringField(u'邮箱', validators=[DataRequired(), Email(), Length(1, 64)])
    username = StringField(u'昵称', validators=[DataRequired(), Length(1,64),
                                              Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                u'昵称必须包含数字，字母或下划线')])
    confirmed = BooleanField(u'确认状态')
    role = SelectField(u'角色', coerce=int)
    name = StringField(u'真实姓名', validators=[Length(0, 64)])
    location = StringField(u'地区', validators=[Length(0,64)])
    about_me = TextAreaField(u'个人简介')
    submit = SubmitField(u'修改')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in
                             Role.query.order_by(Role.name).all()]

        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and\
            User.query.filter_by(email=field.data).first():
            raise ValidationError(u'邮箱已存在')


    def validate_username(self, field):
        if field.data != self.user.username and\
            User.query.filter_by(username=field.data).first():
            raise ValidationError(u'昵称已存在')

class PostForm(FlaskForm):
    body = TextAreaField(u'正文', validators=[DataRequired()])
    submit = SubmitField(u'提交')
