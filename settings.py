# -*- coding: utf-8 -*-
import os
from peewee import SqliteDatabase

db = SqliteDatabase('test.db')

PORT = 8080
HOST = '127.0.0.1'

BASE_PATH = os.getcwd()
URLS = os.path.join(BASE_PATH, 'urls.py')
VIEWS = os.path.join(BASE_PATH, 'views.py')
TEMPLATES = os.path.join(BASE_PATH, 'templates/')
STATIC = os.path.join(BASE_PATH, 'static/')
MEDIA = os.path.join(BASE_PATH, 'media/')

FROM_EMAIL = 'alex.ligth.it@yandex.ru'
FROM_EMAIL_LOGIN = 'alex.ligth.it'
FROM_EMAIL_PASSWORD = '123456qwe!@#'
SMTP = 'smtp.yandex.ru'

RECAPTCHA_PUBLIC_KEY = '6LeGYBITAAAAAPV2aOh_uXRBoYgUqK0X2ZokQseI'
RECAPTCHA_PRIVATE_KEY = '6LeGYBITAAAAACBWuj8-A1c6cAaG57sSmTawShDf'

mime_types = {
    'css': 'text/css',
    'js': 'application/javascript',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'png': 'image/png',
    'ttf': 'application/x-font-ttf',
    'html': 'text/html',
    'ico': 'image/x-icon',
}