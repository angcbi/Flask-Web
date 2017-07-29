#!/usr/bin/env python
# coding=utf-8
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError

from ..models import User


class LoginForm(FlaskForm):
    email = StringField(u'邮箱', validators=[DataRequired(), Length(1, 64), Email()]) 
    password= PasswordField(u'密码', validators=[DataRequired()])
    remember_me = BooleanField(u'记住我')
    submit = SubmitField(u'登录')


class RegisterForm(FlaskForm):
    email = StringField(u'邮箱', validators=[DataRequired(), Length(1, 64), Email()]) 
    username = StringField(u'昵称', validators=[DataRequired(), Length(1, 64)]) 
    password = PasswordField(u'密码', validators=[DataRequired(),
                                                    EqualTo('password2', message=u'两次密码不匹配')])
    password2 = PasswordField(u'确认密码', validators=[DataRequired()])
    submit = SubmitField(u'注册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(u'邮箱已存在')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError(u'昵称已存在')

 
class ModifyPasswordForm(FlaskForm):
    password = PasswordField(u'原密码', validators=[DataRequired()])
    password1 = PasswordField(u'新密码', validators=[DataRequired(), EqualTo('password2', message=u'两次密码不一致')])
    password2 = PasswordField(u'确认密码', validators=[DataRequired()])
    submit = SubmitField(u'确认')


class ResetPasswordForm(FlaskForm):
    email = StringField(u'邮箱', validators=[DataRequired(), Email()])
    submit = SubmitField(u'确定')

class ResetForm(FlaskForm):
    password = PasswordField(u'新密码', validators=[DataRequired(), EqualTo('password2', message=u'两次密码不一致')])
    password2 = PasswordField(u'确认密码', validators=[DataRequired()])
    submit = SubmitField(u'确定')

