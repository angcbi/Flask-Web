# -*- coding: utf-8 -*-

from flask_login import login_required, current_user

from . import oauth2


@login_required
@ouath2.route('/client', methods=['GET', 'POST'])
def client():
    pass


