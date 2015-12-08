#!/usr/bin/env python
# -*- coding: utf-8 -*-
import Cookie
import hashlib
import traceback
import urllib
import urllib2

import db
import os
import re
from wsgiref.simple_server import make_server
from jinja2 import Environment, FileSystemLoader
from smtplib import SMTP_SSL

md5 = lambda x: hashlib.md5(x).hexdigest()

# users = None
c = Cookie.SimpleCookie()
BASE_PATH = os.getcwd()
templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
import os
stylesheets = os.listdir('stylesheets')


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


def send_message(toaddr, message):
    # Формируем сообщение
    fromaddr = 'alex.ligth.it@yandex.ru'
    # toaddr = 'la2gg@yandex.ru'
    subj = 'Регистрация прошла успешно!!!'
    msg_txt = 'Notice:\n\n ' + 'Русские буквы' + '\n\nBye!'
    msg = "From: {}\nTo: {}\nSubject: {}\n\n{}".format(fromaddr, toaddr, subj, message)

    # Отправляем сообщение
    smtp = SMTP_SSL()
    smtp.connect('smtp.yandex.ru')
    smtp.login('alex.ligth.it', '123456qwe!@#')
    smtp.sendmail(fromaddr, toaddr, msg)
    smtp.quit()


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
    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('index.html')

    # region Удалить
    database = db.Database()
    users = database.get_all_users()
    # endregion

    args = {'users': users, 'title': u'Главная'}
    return status, headers, template, args,


def contacts(environ):
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]

    template = templates.get_template('contacts.html')
    args = {'title': u'Контакты'}
    return status, headers, template, args,


def personal_account(environ):
    try:
        Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_name"].value
    except:
        status = '301 Moved'
        refer = 'http://localhost:8053'
        headers = [
            ('Content-type', 'text/html; charset=utf-8'),
            ('Location', refer)
        ]
        # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
        template = templates.get_template('500.html')
        args = {}
        return status, headers, template, args,

    errors = {}
    data = {}
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]

    if environ['REQUEST_METHOD'] == 'POST':
        content_length = int(environ.get('CONTENT_LENGTH') or '0')
        raw_data = environ['wsgi.input'].read(content_length)

        query = [query.split('=') for query in raw_data.split('&') if query]
        data_form = dict()
        for q in query:
            data_form[q[0]] = q[1]

        if data_form.has_key('password'):
            password = urllib.unquote(data_form['password'])
            data['password'] = password
            is_error = False

            re_password = re.compile('[a-zA-Z0-9]{6,16}')
            res_password = re_password.search(password)
            if not res_password:
                errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
                is_error = True
            elif len(res_password.group()) != len(password):
                errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
                is_error = True

            database = db.Database()
            if not is_error:
                user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_id"].value
                user_db = database.get_user_from_id(user_id)

                password = md5(password)
                user = User(user_id, user_db.lastName.encode('utf8'), user_db.firstName.encode('utf8'), user_db.login,
                            password, user_db.email, user_db.birthDate, user_db.mobilePhone)
                database.edit_user(user)

                status = '301 Moved'
                refer = 'http://localhost:8053/personal_account'

                headers = [
                    ('Content-type', 'text/html; charset=utf-8'),
                    ('Location', refer),
                ]

        else:
            first_name = urllib.unquote(data_form['first_name'])
            data['first_name'] = urllib.unquote(data_form['first_name']).decode('utf8')
            last_name = urllib.unquote(data_form['last_name'])
            data['last_name'] = urllib.unquote(data_form['last_name']).decode('utf8')
            login = urllib.unquote(data_form['login'])
            data['login'] = login
            email = urllib.unquote(data_form['email'])
            data['email'] = email
            birthDate = urllib.unquote(data_form['birthDate'])
            data['birthDate'] = birthDate
            mobilePhone = urllib.unquote(data_form['mobilePhone'])
            data['mobilePhone'] = mobilePhone
            is_error = False

            re_name = re.compile('[a-zA-Zа-яА-Я]{1,25}')
            res_last_name = re_name.search(last_name)
            if not res_last_name:
                errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'
                is_error = True
            elif len(res_last_name.group()) != len(last_name):
                errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'
                is_error = True

            res_first_name = re_name.search(first_name)
            if not res_first_name:
                errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'
                is_error = True
            elif len(res_first_name.group()) != len(first_name):
                errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'
                is_error = True

            re_email = re.compile('[^@]+@[^@]+\.[^@]+')
            res_email = re_email.search(email)
            if not res_email:
                errors['email'] = u'Введите корректный Емейл'
                is_error = True
            elif len(res_email.group()) != len(email):
                errors['email'] = u'Введите корректный Емейл'
                is_error = True

            import datetime
            try:
                datetime.datetime.strptime(birthDate, '%Y-%m-%d').date()
            except Exception:
                errors['birthDate'] = u'\nВведите корректную дату'
                is_error = True

            re_mobile = re.compile('[0-9]{3,3}-[0-9]{7,7}')
            res_mobile = re_mobile.search(mobilePhone)
            if not res_mobile:
                errors['mobilePhone'] = u'Введите корректный Мобильный телефон'
                is_error = True
            elif len(res_mobile.group()) != len(mobilePhone):
                errors['mobilePhone'] = u'Введите корректный Мобильный телефон'
                is_error = True

            re_login = re.compile('[a-zA-Z0-9]{1,25}')
            res_login = re_login.search(login)
            if not res_login:
                errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
                is_error = True
            elif len(res_login.group()) != len(login):
                errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
                is_error = True

            database = db.Database()
            if not is_error:
                user_check = database.get_user_from_login(login)
                user_id = None
                try:
                    user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_id"].value
                except:
                    user_id = None

                if user_check:
                    if user_check.id != int(user_id):
                        errors['login'] = u"Пользователь с таким логином уже существует"
                        is_error = True

                    else:
                        user = User(user_id, last_name, first_name, login, user_check.password,
                                    email, birthDate, mobilePhone)
                        database.edit_user(user)

                        first_name = urllib.unquote(data_form['first_name']).decode('utf8')
                        last_name = urllib.unquote(data_form['last_name']).decode('utf8')
                        cookie = Cookie.SimpleCookie()
                        cookie['user_name'] = first_name.encode('utf8').title() + ' ' \
                                              + last_name[0].encode('utf8').title() + '.'

                        cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())

                        headers = [
                            ('Content-type', 'text/html; charset=utf-8'),
                            cookieheaders,
                        ]
    else:
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

    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('personal_account.html')

    args = {'errors': errors, 'data': data, 'title': u'Личный кабинет'}
    return status, headers, template, args,


def login(environ):
    # global c
    try:
        Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_name"].value
        status = '301 Moved'
        refer = 'http://localhost:8053'
        headers = [
            ('Content-type', 'text/html; charset=utf-8'),
            ('Location', refer)
        ]
        # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
        template = templates.get_template('500.html')
        args = {}
        return status, headers, template, args,
    except:
        pass

    # login и password потом удалить
    login = ''
    password = ''
    errors = {}
    refer = ''

    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]

    if environ['REQUEST_METHOD'] == 'POST':
        content_length = int(environ.get('CONTENT_LENGTH') or '0')
        raw_data = environ['wsgi.input'].read(content_length)

        query = [query.split('=') for query in raw_data.split('&') if query]
        data = dict()
        for q in query:
            data[q[0]] = q[1]
        login = urllib.unquote(data['login']).decode('utf8')
        password = urllib.unquote(data['password']).decode('utf8')
        is_error = False

        re_password = re.compile('[a-zA-Z0-9]{6,16}')
        res_password = re_password.search(password)
        if not res_password:
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
            is_error = True
        elif len(res_password.group()) != len(password):
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
            is_error = True

        re_login = re.compile('[a-zA-Z0-9]{1,25}')
        res_login = re_login.search(login)
        if not res_login:
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
            is_error = True
        elif len(res_login.group()) != len(login):
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
                    cookie = Cookie.SimpleCookie()
                    cookie['user_name'] = user_db.firstName.encode('utf8').title() + ' ' \
                                          + user_db.lastName[0].encode('utf8').title() + '.'
                    cookie['user_id'] = user_db.id

                    cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())
                    cookieheaders1 = ('Set-Cookie', cookie['user_id'].OutputString())

                    status = '301 Moved'
                    refer = 'http://localhost:8053'

                    headers = [
                        ('Content-type', 'text/html; charset=utf-8'),
                        ('Location', refer),
                        cookieheaders,
                        cookieheaders1
                    ]

                else:
                    errors['user'] = u"Неверное имя пользователя или пароль"

    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('login.html')
    args = {'login': login, 'password': password, 'errors': errors, 'title': u'Вход'}
    return status, headers, template, args,


def delete_account(environ):
    try:
        Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_name"].value
    except:
        status = '301 Moved'
        refer = 'http://localhost:8053'
        headers = [
            ('Content-type', 'text/html; charset=utf-8'),
            ('Location', refer)
        ]
        # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
        template = templates.get_template('500.html')
        args = {}
        return status, headers, template, args,

    cookie = Cookie.SimpleCookie()
    user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_id"].value
    cookie['user_name'] = ""
    cookie['user_id'] = ""
    cookie['user_name']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
    cookie['user_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'

    cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())
    cookieheaders1 = ('Set-Cookie', cookie['user_id'].OutputString())

    status = '301 Moved'
    refer = 'http://localhost:8053'

    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
        ('Location', refer),
        cookieheaders,
        cookieheaders1
    ]
    database = db.Database()
    database.delete_user_from_id(user_id)

    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('index.html')
    args = {}
    return status, headers, template, args,


def sign_out(environ):
    try:
        Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_name"].value
    except:
        status = '301 Moved'
        refer = 'http://localhost:8053'
        headers = [
            ('Content-type', 'text/html; charset=utf-8'),
            ('Location', refer)
        ]
        # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
        template = templates.get_template('500.html')
        args = {}
        return status, headers, template, args,

    cookie = Cookie.SimpleCookie()
    cookie['user_name'] = ""
    cookie['user_id'] = ""
    cookie['user_name']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
    cookie['user_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'

    cookieheaders = ('Set-Cookie', cookie['user_name'].OutputString())
    cookieheaders1 = ('Set-Cookie', cookie['user_id'].OutputString())

    status = '301 Moved'
    refer = 'http://localhost:8053'

    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
        ('Location', refer),
        cookieheaders,
        cookieheaders1
    ]

    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('index.html')
    args = {}
    return status, headers, template, args,


def register(environ):
    try:
        Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))["user_name"].value
        status = '301 Moved'
        refer = 'http://localhost:8053'
        headers = [
            ('Content-type', 'text/html; charset=utf-8'),
            ('Location', refer)
        ]
        # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
        template = templates.get_template('500.html')
        args = {}
        return status, headers, template, args,
    except:
        pass

    errors = {}
    data = {}
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]

    if environ['REQUEST_METHOD'] == 'POST':
        content_length = int(environ.get('CONTENT_LENGTH') or '0')
        raw_data = environ['wsgi.input'].read(content_length)

        query = [query.split('=') for query in raw_data.split('&') if query]
        data_form = dict()
        for q in query:
            data_form[q[0]] = q[1]

        first_name = urllib.unquote(data_form['first_name'])
        data['first_name'] = urllib.unquote(data_form['first_name']).decode('utf8')
        last_name = urllib.unquote(data_form['last_name'])
        data['last_name'] = urllib.unquote(data_form['last_name']).decode('utf8')
        login = urllib.unquote(data_form['login'])
        data['login'] = login
        password = urllib.unquote(data_form['password'])
        data['password'] = password
        email = urllib.unquote(data_form['email'])
        data['email'] = email
        birthDate = urllib.unquote(data_form['birthDate'])
        data['birthDate'] = birthDate
        mobilePhone = urllib.unquote(data_form['mobilePhone'])
        data['mobilePhone'] = mobilePhone
        captcha = data_form['g-recaptcha-response']
        is_error = False

        re_password = re.compile('[a-zA-Z0-9]{6,16}')
        res_password = re_password.search(password)
        if not res_password:
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
            is_error = True
        elif len(res_password.group()) != len(password):
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
            is_error = True

        re_name = re.compile('[a-zA-Zа-яА-Я]{1,25}')
        res_last_name = re_name.search(last_name)
        if not res_last_name:
            errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'
            is_error = True
        elif len(res_last_name.group()) != len(last_name):
            errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'
            is_error = True

        res_first_name = re_name.search(first_name)
        if not res_first_name:
            errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'
            is_error = True
        elif len(res_first_name.group()) != len(first_name):
            errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'
            is_error = True

        re_email = re.compile('[^@]+@[^@]+\.[^@]+')
        res_email = re_email.search(email)
        if not res_email:
            errors['email'] = u'Введите корректный Емейл'
            is_error = True
        elif len(res_email.group()) != len(email):
            errors['email'] = u'Введите корректный Емейл'
            is_error = True

        import datetime
        try:
            datetime.datetime.strptime(birthDate, '%Y-%m-%d').date()
        except Exception:
            errors['birthDate'] = u'\nВведите корректную дату'
            is_error = True

        re_mobile = re.compile('[0-9]{3,3}-[0-9]{7,7}')
        res_mobile = re_mobile.search(mobilePhone)
        if not res_mobile:
            errors['mobilePhone'] = u'Введите корректный Мобильный телефон'
            is_error = True
        elif len(res_mobile.group()) != len(mobilePhone):
            errors['mobilePhone'] = u'Введите корректный Мобильный телефон'
            is_error = True

        re_login = re.compile('[a-zA-Z0-9]{1,25}')
        res_login = re_login.search(login)
        if not res_login:
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
            is_error = True
        elif len(res_login.group()) != len(login):
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
            is_error = True


        result_captcha = submit('6LeGYBITAAAAACBWuj8-A1c6cAaG57sSmTawShDf', captcha)
        if not result_captcha:
            errors['captcha'] = u"\nCaptcha обязателен для заполнения"

        database = db.Database()

        user_db = database.get_user_from_login(login)
        if user_db is not None:
            errors['login'] = u"Пользователь с таким логином уже существует"
            is_error = True

        if not is_error:
            password_tmp = password
            password = md5(password)
            # password = hashlib.md5(password)
            # password = password.hexdigest()
            user = User(None, last_name, first_name, login, password, email, birthDate, mobilePhone)
            database.add_user(user)
            user_db_new = database.get_user_from_login(login)

            message = '''Регистрация прошла успешно.
                        Имя: {}
                        Фамилия: {}
                        Логин: {}
                        Пароль: {}
                        День рождения: {}
                        Мобильный телефон: {}''' \
                .format(last_name, first_name, login, password_tmp, birthDate, mobilePhone)

            send_message(email, message)

            first_name = urllib.unquote(data_form['first_name']).decode('utf8')
            last_name = urllib.unquote(data_form['last_name']).decode('utf8')
            c['user_id'] = user_db_new.id
            c['user_name'] = first_name.encode('utf8').title() + ' ' \
                             + last_name[0].encode('utf8').title() + '.'

            status = '301 Moved'
            refer = 'http://localhost:8053'

            headers = [
                ('Content-type', 'text/html; charset=utf-8'),
                ('Location', refer)
            ]

    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('register.html')

    args = {'errors': errors, 'data': data, 'title': u'Регистрация'}
    return status, headers, template, args,


def base(environ):
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]
    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('base.html')
    args = {'items': environ.items()}
    return status, headers, template, args,


def view_404(environ):
    status = '404 NOT FOUND'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]
    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('404.html')
    args = {'title': u'404 СТРАНИЦА НЕ НАЙДЕНА'}
    return status, headers, template, args,


def view_500(environ, error):
    status = '500 INTERNAL SERVER ERROR'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]
    # templates = Environment(loader=FileSystemLoader(BASE_PATH + '/templates'))
    template = templates.get_template('500.html')
    args = {'error_message': error.message, 'error_info': traceback.format_exc(),
            'title': u'500 ВНУТРЕННЯЯ ОШИБКА СЕРВЕРА'}
    return status, headers, template, args,


def test(environ):
    status = '200 OK'
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
    ]
    css = Environment(loader=FileSystemLoader(BASE_PATH + '/stylesheets'))
    template = templates.get_template('stylesheet.css')
    args = {}
    return status, headers, template, args,


def get_view(environ):
    # Определяем, какую страницу нужно показать клиенту

    # Определяем, по какаму адресу перешел клиент
    request_url = environ['PATH_INFO']

    # Словарь с сылками и методами, чтобы получить эти страницы
    urls = {
        '/': index,
        '/index': index,
        '/contacts': contacts,
        '/personal_account': personal_account,
        '/login': login,
        '/sign_out': sign_out,
        '/register': register,
        '/base': base,
        '/delete_account': delete_account,
        '/stylesheet.css': test
    }

    try:
        return urls[request_url]
    except KeyError:
        return view_404


def application(environ, start_response):
    database = db.Database()
    database.create_db()
    # Определяем, какую страницу нужно показать клиенту
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
    httpd = make_server('localhost', 8053, application)
    httpd.serve_forever()
