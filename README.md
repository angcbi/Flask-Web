# Flask-Web 

* 本项目根据<<Flask Web开发: 基于Python的Web开发实战>>书而来
是学习Flask开发的一个记录
* 除了实现<<Flask Web开发>>介绍的功能外，也实现了其他功能


## Flask-JWT
集成Flask-JWT，采用JWT实现API的认证功能

## PyJWT
 采用PyJWT，实现自定义JWT认证功能。支持
    1. 自定义JWT声明
    2. 刷新token
    3. 登录视图装饰器
    4. 获取登录用户

## OAuth Client 
采用Flask-OAuthlib实现新浪微博登录
    1. 需先在[微博开发平台](http://open.weibo.com/development)注册应用，设置回调地址和测试账号
    2. 授权成功后，在session中设置对应的值，关联本地系统账号(注册或登录)
    3. 管理后，即可用微博登录

## OAuth2 Server
采用Flask-OAuthlib实现OAuth2 Server


