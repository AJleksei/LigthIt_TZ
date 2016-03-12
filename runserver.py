# -*- coding: utf-8 -*-
from wsgiref.simple_server import make_server
from peewee import *
from models import Users
import settings
import models

#db = SqliteDatabase('people.db')

import settings
from wsgi import application

if __name__ == '__main__':
    models.create_tables()
    print 'Runed server on {}:{}'.format(settings.HOST, settings.PORT)
    httpd = make_server(settings.HOST, settings.PORT, application)
    httpd.serve_forever()