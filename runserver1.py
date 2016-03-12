#!/usr/bin/env python
# -*- coding: utf-8 -*-
import Cookie
import cgi
import hashlib
import os
import re
import traceback
import urllib
import urllib2
from smtplib import SMTP_SSL
from wsgiref.simple_server import make_server

import datetime
from jinja2 import Environment, FileSystemLoader

import db

md5 = lambda x: hashlib.md5(x).hexdigest()

BASE_PATH = os.getcwd()
HOST = 'localhost'
PORT = 8053
BASE_ADDR = 'http://' + HOST + ':' + str(PORT)
templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))


re_last_name = re.compile('[a-zA-Zа-яА-Я]{1,25}')
re_first_name = re.compile('[a-zA-Zа-яА-Я]{1,25}')
re_login = re.compile('[a-zA-Z0-9]{1,25}')
re_password = re.compile('[a-zA-Z0-9]{6,16}')
re_email = re.compile('[^@]+@[^@]+\.[^@]+')
re_mobile = re.compile('[0-9]{3}-[0-9]{7}')
re_birthday = re.compile('[0-9]{4}-[0-9]{2}-[0-9]{2}')


def validate_last_name(last_name):
    res_last_name = re_last_name.search(last_name)
    if not res_last_name:
        return False
    return True


def validate_first_name(first_name):
    if not re_first_name.search(first_name):
        return False
    return True


def validate_login(login):
    if not re_login.search(login):
        return False
    return True


def validate_password(password):
    if not re_password.search(password):
        return False
    return True


def validate_email(email):
    if not re_email.search(email):
        return False
    return True


def validate_mobile(mobile):
    if not re_mobile.search(mobile):
        return False
    return True


def validate_birthday(birthday):
    if not re_birthday.search(birthday):
        return False
    try:
        datetime.datetime.strptime(birthday, '%Y-%m-%d').date()
    except Exception:
        return False
    return True


def redirect_to_home():
    status = '301 Moved'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
        ('Location', BASE_ADDR)
    ]
    template = templates.get_template('index.html')
    args = {}
    return status, headers, template, args,


def get_request_data(environ):
    content_length = int(environ.get('CONTENT_LENGTH') or '0')
    raw_data = environ['wsgi.input'].read(content_length)

    query = [query.split('=') for query in raw_data.split('&') if query]
    data_form = dict()
    for q in query:
        data_form[q[0]] = q[1]

    return data_form


def is_user_logged(environ):
    user = None
    try:
        user = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_name"].value
    except Exception:
        return user
    return user


class User:
    id = None

    def __init__(self, id, lastName, firstName, login, password, email, birthDate,
                 mobilePhone):
        self.id = id
        self.lastName = lastName.decode('utf8')
        self.firstName = firstName.decode('utf8')
        self.login = login
        self.password = password
        self.email = email
        self.birthDate = birthDate
        self.mobilePhone = mobilePhone


# Метод для отправки сообщений на емейл
def send_email(toaddr, subject, message):
    # Формируем сообщение
    fromaddr = 'alex.ligth.it@yandex.ru'
    msg = "From: {}\nTo: {}\nSubject: {}\n\n{}".format(fromaddr, toaddr, subject, message)

    # Отправляем сообщение
    smtp = SMTP_SSL()
    smtp.connect('smtp.yandex.ru')
    smtp.login('alex.ligth.it', '123456qwe!@#')
    smtp.sendmail(fromaddr, toaddr, msg)
    smtp.quit()


# Проверка валидности введеной капчи
def submit(secret, response):
    if not response or not secret:
        return False

    def encode_if_necessary(s):
        if isinstance(s, unicode):
            return s.encode('utf-8')
        return s

    params = urllib.urlencode({
        'secret': encode_if_necessary(secret),
        'response': encode_if_necessary(response),
    })

    request = urllib2.Request(
        url="https://www.google.com/recaptcha/api/siteverify",
        data=params,
        headers={
            "Content-type": "application/x-www-form-urlencoded",
            "User-agent": "reCAPTCHA Python"
        }
    )

    httpresp = urllib2.urlopen(request)

    return_values = httpresp.read().splitlines();
    httpresp.close();

    return_code = return_values[1]

    if return_code.find('true'):
        return True
    else:
        return False


def index(environ):
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]
    template = templates.get_template('index.html')

    args = {}
    return status, headers, template, args,


def contacts(environ):
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]

    template = templates.get_template('contacts.html')
    args = {}
    return status, headers, template, args,


def personal_account(environ):
    user_id = 0
    # Если пользователь не залогинен, отправляем его на главную страницу
    if not is_user_logged(environ):
        return redirect_to_home()

    errors = {}
    data = {}
    is_error = False
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]

    # Если это метод POST
    if environ['REQUEST_METHOD'] == 'POST':
        data_form = get_request_data(environ)

        # Если в форме есть поле password
        if data_form.has_key('password'):
            password = urllib.unquote(data_form['password']).strip()
            data['password'] = password

            if not validate_password(password):
                errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
                is_error = True

            database = db.Database()
            # Если ошибок нет
            if not is_error:
                user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_id"].value
                user_db = database.get_user_from_id(user_id)

                password = md5(password)
                # Изменяем пароль в БД
                user = User(user_id, user_db.lastName.encode('utf8'), user_db.firstName.encode('utf8'),
                            user_db.login,
                            password, user_db.email, user_db.birthDate, user_db.mobilePhone)
                database.edit_user(user)

        else:
            first_name = urllib.unquote(data_form['first_name']).strip()
            data['first_name'] = urllib.unquote(data_form['first_name']).decode('utf8').strip()
            last_name = urllib.unquote(data_form['last_name']).strip()
            data['last_name'] = urllib.unquote(data_form['last_name']).decode('utf8').strip()
            login = data['login'] = urllib.unquote(data_form['login']).strip()
            email = data['email'] = urllib.unquote(data_form['email']).strip()
            birthDate = data['birthDate'] = urllib.unquote(data_form['birthDate']).strip()
            mobilePhone = data['mobilePhone'] = urllib.unquote(data_form['mobilePhone']).strip()

            if not validate_last_name(last_name):
                errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'
                is_error = True

            if not validate_first_name(first_name):
                errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'
                is_error = True

            if not validate_email(email):
                errors['email'] = u'Введите корректный Емейл'
                is_error = True

            if not validate_birthday(birthDate):
                errors['birthDate'] = u'\nВведите корректную дату'
                is_error = True

            if not validate_mobile(mobilePhone):
                errors['mobilePhone'] = u'Введите корректный Мобильный телефон'
                is_error = True

            if not validate_login(login):
                errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
                is_error = True

            database = db.Database()
            # Если ошибок нет
            if not is_error:
                user_check = database.get_user_from_login(login)
                user_id = None
                try:
                    user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_id"].value
                except:
                    user_id = None

                if user_check:
                    # Если id залогиненого пользователя не равно id пользователя из БД
                    # (если такой ник существует в БД и это не его ник)
                    if user_check.id != int(user_id):
                        errors['login'] = u"Пользователь с таким логином уже существует"
                        is_error = True

                    else:
                        # Сохраняем изменения в БД
                        user = User(user_id, last_name, first_name, login, user_check.password,
                                    email, birthDate, mobilePhone)
                        database.edit_user(user)

                        first_name = urllib.unquote(data_form['first_name']).decode('utf8')
                        last_name = urllib.unquote(data_form['last_name']).decode('utf8')
                        # Обновляем cookie
                        cookie = Cookie.SimpleCookie()
                        cookie['user_name'] = first_name.encode('utf8').title() + ' ' \
                                              + last_name[0].encode('utf8').title() + '.'

                        cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())

                        headers = [
                            ('Content-type', 'text/html; charset=utf-8'),
                            cookieheaders,
                        ]
    else:
        # Если это GET запрос
        database = db.Database()
        user_id = None
        try:
            user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_id"].value
        except:
            user_id = None
        user_db = database.get_user_from_id(user_id)
        if user_db:
            data['first_name'] = user_db.firstName
            data['last_name'] = user_db.lastName
            data['login'] = user_db.login
            data['email'] = user_db.email
            data['birthDate'] = user_db.birthDate
            data['mobilePhone'] = user_db.mobilePhone

    template = templates.get_template('personal_account.html')

    args = {'errors': errors, 'data': data}
    return status, headers, template, args,


def load_avatar(environ):
    user_id = 0
    if not is_user_logged(environ):
        return redirect_to_home()

    errors = {}
    data = {}

    status = '200 OK'
    #status = '301 Moved'
    #refer = BASE_ADDR
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
        #('Location', refer)
    ]

    if environ['REQUEST_METHOD'] == 'POST':
        formdata = cgi.FieldStorage(environ=environ, fp=environ['wsgi.input'])
        if 'avatar' in formdata and formdata['avatar'].filename != '':
            file_data = formdata['avatar'].file.read()
            # Ищем расширение файла
            start = formdata['avatar'].filename.find('.')
            end = len(formdata['avatar'].filename)

            # Получаем расширение файла
            filename = formdata['avatar'].filename[start:end]

            # В название картинки пишем id юзера, чтобы не было конфликтов
            # Если пользователь загрузит еще аватарку, то старая перезапишется
            target = os.path.join('uploads', user_id + filename)
            f = open(target, 'wb')
            f.write(file_data)
            f.close()
    else:
        # Если это GET запрос
        database = db.Database()
        user_id = None
        try:
            user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_id"].value
        except:
            user_id = None
        user_db = database.get_user_from_id(user_id)
        if user_db:
            data['first_name'] = user_db.firstName
            data['last_name'] = user_db.lastName
            data['login'] = user_db.login
            data['email'] = user_db.email
            data['birthDate'] = user_db.birthDate
            data['mobilePhone'] = user_db.mobilePhone

    template = templates.get_template('personal_account.html')

    args = {'errors': errors, 'data': data}
    return status, headers, template, args,


def login(environ):
    # Если пользователь залогинен, он не сможет попасть на страницу login
    if is_user_logged(environ):
        return redirect_to_home()

    errors = {}

    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]

    if environ['REQUEST_METHOD'] == 'POST':
        data = get_request_data(environ)

        login = urllib.unquote(data['login']).decode('utf8')
        password = urllib.unquote(data['password']).decode('utf8')
        is_error = False

        if not validate_password(password):
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
            is_error = True

        if not validate_login(login):
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
            is_error = True

        if not is_error:
            database = db.Database()

            user_db = database.get_user_from_login(login)
            if user_db is None:
                errors['user'] = u"Неверное имя пользователя или пароль"
            else:
                password = md5(password)

                if user_db.password == password:
                    # Сохраняем в cookie данные, что пользователь залогинелся
                    cookie = Cookie.SimpleCookie()
                    cookie['user_name'] = user_db.firstName.encode('utf8').title() + ' ' \
                                          + user_db.lastName[0].encode('utf8').title() + '.'
                    cookie['user_id'] = user_db.id

                    cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())
                    cookieheaders1 = ('Set-Cookie', cookie['user_id'].OutputString())

                    status = '301 Moved'
                    refer = BASE_ADDR

                    headers = [
                        ('Content-type', 'text/html; charset=utf-8'),
                        ('Location', refer),
                        cookieheaders,
                        cookieheaders1
                    ]

                else:
                    errors['user'] = u"Неверное имя пользователя или пароль"

    template = templates.get_template('login.html')
    args = {'errors': errors}
    return status, headers, template, args,


def delete_account(environ):
    # Удалить аккаут может только залогиненый пользователь
    if not is_user_logged(environ):
        return redirect_to_home()

    # Очищаем cookie
    cookie = Cookie.SimpleCookie()
    user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_id"].value
    cookie['user_name'] = ""
    cookie['user_id'] = ""
    cookie['user_name']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
    cookie['user_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'

    cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())
    cookieheaders1 = ('Set-Cookie', cookie['user_id'].OutputString())
    status = '301 Moved'
    refer = BASE_ADDR

    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
        ('Location', refer),
        cookieheaders,
        cookieheaders1
    ]
    # Удаляем пользователя из БД
    database = db.Database()
    database.delete_user_from_id(user_id)

    template = templates.get_template('index.html')
    args = {}
    return status, headers, template, args,


def sign_out(environ):
    if not is_user_logged(environ):
        return redirect_to_home()

    # Очищаем cookie
    cookie = Cookie.SimpleCookie()
    cookie['user_name'] = ""
    cookie['user_id'] = ""
    cookie['user_name']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
    cookie['user_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'

    cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())
    cookieheaders1 = ('Set-Cookie', cookie['user_id'].OutputString())

    status = '301 Moved'
    refer = BASE_ADDR

    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
        ('Location', refer),
        cookieheaders,
        cookieheaders1
    ]

    template = templates.get_template('index.html')
    args = {}
    return status, headers, template, args,


def register(environ):
    # Если пользователь залогинелся, он не может попасть на эту страницу
    if is_user_logged(environ):
        return redirect_to_home()

    errors = {}
    data = {}
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]

    if environ['REQUEST_METHOD'] == 'POST':
        data_form = get_request_data(environ)

        first_name = urllib.unquote(data_form['first_name']).strip()
        data['first_name'] = urllib.unquote(data_form['first_name']).decode('utf8').strip()
        last_name = urllib.unquote(data_form['last_name']).strip()
        data['last_name'] = urllib.unquote(data_form['last_name']).decode('utf8').strip()
        login = data['login'] = urllib.unquote(data_form['login']).strip()
        password = data['password'] = urllib.unquote(data_form['password']).strip()
        email = data['email'] = urllib.unquote(data_form['email']).strip()
        birthDate = data['birthDate'] = urllib.unquote(data_form['birthDate']).strip()
        mobilePhone = data['mobilePhone'] = urllib.unquote(data_form['mobilePhone']).strip()
        captcha = data_form['g-recaptcha-response']
        is_error = False

        if not validate_password(password):
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
            is_error = True

        if not validate_login(login):
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
            is_error = True

        if not validate_last_name(last_name):
            errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'
            is_error = True

        if not validate_first_name(first_name):
            errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'
            is_error = True

        if not validate_email(email):
            errors['email'] = u'Введите корректный Емейл'
            is_error = True

        if not validate_birthday(birthDate):
            errors['birthDate'] = u'\nВведите корректную дату'
            is_error = True

        if not validate_mobile(mobilePhone):
            errors['mobilePhone'] = u'Введите корректный Мобильный телефон'
            is_error = True

        if not submit('6LeGYBITAAAAACBWuj8-A1c6cAaG57sSmTawShDf', captcha):
            errors['captcha'] = u"\nCaptcha обязателен для заполнения"

        database = db.Database()

        user_db = database.get_user_from_login(login)
        if user_db is not None:
            errors['login'] = u"Пользователь с таким логином уже существует"
            is_error = True

        if not is_error:
            # Запоминаем пароль, чтобы отправить его на емейл
            # Т.к. пароль сохраняется хешированый, а при сохранении может произойти ошибка,
            # то отправляем сообщение, после сохранения данных в БД
            password_tmp = password
            password = md5(password)
            user = User(None, last_name, first_name, login, password, email, birthDate, mobilePhone)
            database.add_user(user)
            user_db_new = database.get_user_from_login(login)

            # Формируем текст для отправки сообщения на email
            message = '''Регистрация прошла успешно.
                        Имя: {}
                        Фамилия: {}
                        Логин: {}
                        Пароль: {}
                        День рождения: {}
                        Мобильный телефон: {}''' \
                .format(last_name, first_name, login, password_tmp, birthDate, mobilePhone)
            subject = 'Регистрация прошла успешно!!!'
            # отправляем сообщение, с регистрационными данными, на указаный email
            send_email(email, subject, message)

            first_name = urllib.unquote(data_form['first_name']).decode('utf8')
            last_name = urllib.unquote(data_form['last_name']).decode('utf8')

            # Сохраняем cookie, что пользователь залогинен
            cookie = Cookie.SimpleCookie()
            cookie['user_name'] = first_name.encode('utf8').title() + ' ' \
                             + last_name[0].encode('utf8').title() + '.'
            cookie['user_id'] = user_db_new.id

            cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())
            cookieheaders1 = ('Set-Cookie', cookie['user_id'].OutputString())

            status = '301 Moved'
            refer = BASE_ADDR

            headers = [
                ('Content-type', 'text/html; charset=utf-8'),
                ('Location', refer),
                cookieheaders,
                cookieheaders1
            ]

    template = templates.get_template('register.html')

    args = {'errors': errors, 'data': data}
    return status, headers, template, args,


def view_404(environ):
    status = '404 NOT FOUND'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]
    template = templates.get_template('404.html')
    args = {}
    return status, headers, template, args,


def view_500(environ, error):
    status = '500 INTERNAL SERVER ERROR'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]
    template = templates.get_template('500.html')
    args = {'error_message': error.message, 'error_info': traceback.format_exc()}
    return status, headers, template, args,


def get_stylesheets(environ):
    status = '200 OK'
    headers = [
        ('Content-type', 'text/css; charset=utf-8'),
    ]
    stylesheets = Environment(loader=FileSystemLoader(BASE_PATH + '/stylesheets'))
    template = stylesheets.get_template('stylesheet.css')
    args = {}
    return status, headers, template, args,


def get_view(environ):
    # Определяем, по какаму адресу перешел пользователь
    request_url = environ['PATH_INFO']

    # Словарь с сылками и методами, чтобы получить страницы
    urls = {
        '/': index,
        '/index': index,
        '/contacts': contacts,
        '/personal_account': personal_account,
        '/load_avatar': load_avatar,
        '/login': login,
        '/sign_out': sign_out,
        '/register': register,
        '/delete_account': delete_account,
        '/stylesheet.css': get_stylesheets
    }

    try:
        return urls[request_url]
    except KeyError:
        return view_404(environ)


def application(environ, start_response):
    database = db.Database()
    database.create_db()
    # Определяем, какую страницу нужно показать пользователь
    view = get_view(environ)
    try:
        status, headers, template, args = view(environ)
    except Exception, error:
        status, headers, template, args = view_500(environ, error)

    try:
        user = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_name"].value.decode('utf8')
        args['user_name'] = user
    except:
        pass

    start_response(status, headers)
    return [template.render(args).encode('utf-8')]


if __name__ == '__main__':
    httpd = make_server(HOST, PORT, application)
    httpd.serve_forever()