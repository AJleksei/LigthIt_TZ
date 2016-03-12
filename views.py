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

from twisted.spread.pb import respond
import datetime
from smtplib import SMTP_SSL
from jinja2 import Environment, FileSystemLoader
from db import Database, User
from webob import Request, Response, exc
import settings
from models import *


def index(environ):
    request = Request(environ)
    response = Response()
    user_data = get_user_data(request)
    page_content = {'user_data': user_data}
    response.text = templates.get_template('index.html').render(page_content)
    return response


def get_user_data(request):
    if request.cookies.__contains__('session_id'):
        session_id = request.cookies['session_id']
        user = get_user_from_session_id(session_id)
        user_data = {
            'name': '{} {}.'.format(user.first_name, user.last_name[0]),
            'image': user.photo or '/static/img/default.png'
        }
        return user_data
    return None


def contacts(environ):
    response = Response()
    page_content = {}
    response.text = templates.get_template('contacts.html').render(
        page_content)
    return response


def login(environ):
    request = Request(environ)
    response = Response()

    # Если пользователь залогинен, он не сможет попасть на страницу login
    user_auth = is_auth_user(environ)
    if user_auth:
        return redirect_to_home(request)

    errors = {}
    data = {}

    if request.POST:
    #if request.method == 'POST':
        login = data['login'] = request.POST['login'].strip()
        password = data['password'] = request.POST['password'].strip()
        is_error = False

        if not validate_password(password):
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'
            is_error = True

        if not validate_login(login):
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
            is_error = True

        if not is_error:
            #database = Database()

            #user_db = database.get_user_from_login(login)
            user_db = get_user_from_login(login)
            if not user_db:
                errors['user'] = u"Неверное имя пользователя или пароль"
            else:
                password = md5(password)

                if user_db.password == password:
                    # Сохраняем в cookie данные, что пользователь залогинелся
                    response = authorization(response, user_db)
                    #response.status = '301 Moved'
                    #response.location = request.host_url

                    # print response.headers.get('Set-Cookie')
                    #return response
                    redirect_to_home(request, response)
                else:
                    errors['user'] = u"Неверное имя пользователя или пароль"

    page_content = {'errors': errors, 'data': data}

    response.text = templates.get_template('login.html').render(page_content)
    return response


def register(environ):
    request = Request(environ)
    response = Response()

    # Если пользователь залогинелся, он не может попасть на эту страницу
    user_auth = is_auth_user(environ)
    if user_auth:
        return redirect_to_home(request)

    errors = {}
    data = {}

    if request.POST:
    #if request.method == 'POST':
        first_name = data['first_name'] = request.POST['first_name'].strip()
        last_name = data['last_name'] = request.POST['last_name'].strip()
        login = data['login'] = request.POST['login'].strip()
        password = data['password'] = request.POST['password'].strip()
        email = data['email'] = request.POST['email'].strip()
        birth_date = data['birth_date'] = request.POST['birth_date'].strip()
        phone = data['mobilePhone'] = request.POST['mobilePhone'].strip()
        captcha = request.POST['g-recaptcha-response']
        is_error = False

        if not validate_password(password):
            errors[
                'password'] = u'Длина пароля должна быть от 6 до 16 символов'
            is_error = True

        if not validate_login(login):
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
            is_error = True

        if not validate_first_last_name(first_name):
            errors[
                'first_name'] = u'Длина Имени должна быть от 1 до 25 символов'
            is_error = True

        if not validate_first_last_name(last_name):
            errors[
                'last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'
            is_error = True

        if not validate_email(email):
            errors['email'] = u'Введите корректный Емейл'
            is_error = True

        if not validate_birth_date(birth_date):
            errors['birthDate'] = u'\nВведите корректную дату'
            is_error = True

        if not validate_phone(phone):
            errors['mobilePhone'] = u'Введите корректный Мобильный телефон'
            is_error = True

        if not submit(settings.RECAPTCHA_PRIVATE_KEY, captcha):
            errors['captcha'] = u"\nCaptcha обязателен для заполнения"

        #database = Database()

        #user_db = database.get_user_from_login(login)
        user_db = get_user_from_login(login)
        if user_db:
            errors['login'] = u"Пользователь с таким логином уже существует"
            is_error = True

        if not is_error:
            # Запоминаем пароль, чтобы отправить его на емейл
            # Т.к. пароль сохраняется хешированый, а при сохранении может
            #  произойти ошибка, то отправляем сообщение, после сохранения
            # данных в БД
            password_hash = md5(password)
            session_id = create_session_id()
            #user = User(None, last_name, first_name, login, password_hash,
                        #email, birth_date, phone, session_id)
            #database.add_user(user)
            #user_db_new = database.get_user_from_login(login)
            Users.create(last_name=last_name, first_name=first_name,
                         login=login, password=password_hash,
                         email=email, birth_date=birth_date, mobile_phone=phone,
                         session_id=session_id)

            # Формируем текст для отправки сообщения на email
            message = '''Регистрация прошла успешно.
                        Имя: {}
                        Фамилия: {}
                        Логин: {}
                        Пароль: {}
                        День рождения: {}
                        Мобильный телефон: {}''' \
                .format(last_name, first_name, login, password, birth_date,
                        phone)
            subject = 'Регистрация прошла успешно!!!'
            # Отправляем сообщение, с регистрационными данными, на указаный email
            send_email(email, subject, message)

            response.set_cookie('session_id', session_id)

            redirect_to_home(request, response)
            #response.status = '301 Moved'
            #response.refer = request.host_url
            #return response

    page_content = {'errors': errors, 'data': data}
    response.text = templates.get_template('register.html').render(
        page_content)
    return response


def view_404(environ):
    response = Response()
    page_content = {}
    response.status = '404 NOT FOUND'
    response.text = templates.get_template('404.html').render(page_content)
    return response


def view_500(environ, error):
    response = Response()
    page_content = {'error_message': error.message,
                    'error_info': traceback.format_exc()}
    response.status = '500 INTERNAL SERVER ERROR'
    response.text = templates.get_template('500.html').render(page_content)
    return response


def delete_account(environ):
    request = Request(environ)
    response = Response()

    user_auth = is_auth_user(environ)
    # Удалить аккаут может только залогиненый пользователь
    if not user_auth:
        return redirect_to_home(request)

    # Удаляем пользователя из БД
    Users.delete().where(Users.session_id == user_auth.session_id)
    # database = Database()
    # database.delete_user_from_id(user_auth.id)


    response.status = '200 OK'
    page_content = {}
    # Очищаем cookie
    response.delete_cookie('session_id')
    response.text = templates.get_template('delete_account.html').render(
        page_content)
    return response
    #return redirect_to_home(request, response)


def sign_out(environ):
    request = Request(environ)

    user_auth = is_auth_user(environ)
    # Не авторизованный пользователь не может попость на эту страницу
    if not user_auth:
        return redirect_to_home(request)

    response = Response()
    response.delete_cookie('session_id')

    response.status = '200 OK'
    page_content = {}
    response.text = templates.get_template('sign_out.html').render(
        page_content)
    return response

    #return redirect_to_home(request, response)


def personal_account(environ):
    request = Request(environ)
    response = Response()
    user_auth = is_auth_user(environ)
    # Если пользователь не залогинен, отправляем его на главную страницу
    if not user_auth:
        return redirect_to_home(request)

    errors = {}
    data = {}
    args = {}
    is_error = False

    # Если это метод POST
    if request.POST:
    #if request.method == 'POST':
        # Если в форме есть поле password
        if request.POST.__contains__('password'):
            # password = urllib.unquote(data_form['password']).strip()
            password = request.POST['password'].strip()
            data['password'] = password

            if not validate_password(password):
                errors[
                    'password'] = u'Длина пароля должна быть от 6 до 16 символов'
                is_error = True

            # Если ошибок нет
            if not is_error:
                session_id = request.cookies['session_id']
                user_db = get_user_from_session_id(session_id)

                password_hash = md5(password)
                # Изменяем пароль в БД
                user_db.password = password_hash
                user_db.save()
        else:
            first_name = data['first_name'] = request.POST['first_name'].strip()
            last_name = data['last_name'] = request.POST['last_name'].strip()
            login = data['login'] = request.POST['login'].strip()
            email = data['email'] = request.POST['email'].strip()
            birth_date = data['birthDate'] = request.POST['birthDate'].strip()
            mobilePhone = data['mobilePhone'] = request.POST['mobilePhone'].strip()

            if not validate_first_last_name(first_name):
                errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'
                is_error = True

            if not validate_first_last_name(last_name):
                errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'
                is_error = True

            if not validate_email(email):
                errors['email'] = u'Введите корректный Емейл'
                is_error = True

            if not validate_birth_date(birth_date):
                errors['birthDate'] = u'\nВведите корректную дату'
                is_error = True

            if not validate_phone(mobilePhone):
                errors['mobilePhone'] = u'Введите корректный Мобильный телефон'
                is_error = True

            if not validate_login(login):
                errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'
                is_error = True

            # Если ошибок нет
            if not is_error:
                session_id = request.cookies['session_id']
                user_db = get_user_from_session_id(session_id)
                if user_db:
                    user_check_login = get_user_from_login(login)
                    if user_check_login:
                        errors['login'] = u"Пользователь с таким логином уже существует"
                        is_error = True

                    else:
                        # Сохраняем изменения в БД
                        user_db.login = login
                        user_db.first_name = first_name
                        user_db.last_name = last_name
                        user_db.email = email
                        user_db.birth_date = birth_date
                        user_db.mobile_phone = mobilePhone
                        user_db.save()
                        # Обновляем cookie

    elif request.method == 'GET' or request.POST and\
            request.POST.__contains__('password'):
        # Если это GET запрос или POST с изменением пароля
        session_id = request.cookies['session_id']
        user_db = get_user_from_session_id(session_id)
        if user_db:
            data['first_name'] = user_db.first_name
            data['last_name'] = user_db.last_name
            data['login'] = user_db.login
            data['email'] = user_db.email
            data['birthDate'] = user_db.birth_date
            data['mobilePhone'] = user_db.mobile_phone

    args['data'] = data
    #args = {'errors': errors, 'data': data}
    args['errors'] = errors
    response.text = templates.get_template('personal_account.html').render(args)
    return response


def static(environ):
    request = Request(environ)
    response = Response()

    extension = os.path.splitext(request.path_url)[1].replace('.', '')
    mime = settings.mime_types.get(extension, 'text/html')

    file_path = os.path.join(settings.STATIC,
                             request.path_info.replace('/static/', ''))

    if mime == 'image/x-icon':
        file_path = os.path.join(settings.STATIC,
                                 request.path_info.replace('/', ''))

    try:
        file = open(file_path, 'rb')
        response.body = file.read()
    except:
        return view_404(environ)
    else:
        response.content_type = mime
    return response


def load_avatar(environ):
    request = Request(environ)
    user_id = 0

    user_auth = is_auth_user(environ)
    if not user_auth:
        return redirect_to_home(request)

    errors = {}
    data = {}

    status = '200 OK'
    # status = '301 Moved'
    # refer = BASE_ADDR
    headers = [
        ('Content-type', 'text/html; charset=utf-8'),
        # ('Location', refer)
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
        database = Database()
        user_id = None
        try:
            user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))[
                "user_id"].value
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


def get_stylesheets(environ):
    status = '200 OK'
    headers = [
        ('Content-type', 'text/css; charset=utf-8'),
    ]
    stylesheets = Environment(
        loader=FileSystemLoader(settings.BASE_PATH + '/stylesheets'))
    template = stylesheets.get_template('stylesheet.css')
    args = {}
    return status, headers, template, args,


md5 = lambda x: hashlib.md5(x).hexdigest()

templates = Environment(loader=FileSystemLoader(settings.BASE_PATH + '/templates'))

re_first_last_name = re.compile('[a-zA-Zа-яА-Я]{1,25}')
re_login = re.compile('[a-zA-Z0-9]{1,25}')
re_password = re.compile('[a-zA-Z0-9]{6,16}')
re_email = re.compile('[^@]+@[^@]+\.[^@]+')
re_phone = re.compile('[0-9]{3}-[0-9]{7}')
re_birth_date = re.compile('[0-9]{4}-[0-9]{2}-[0-9]{2}')


def validate_first_last_name(first_last_name):
    if not re_first_last_name.search(first_last_name):
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


def validate_phone(phone):
    if not re_phone.search(phone):
        return False
    return True


def validate_birth_date(birth_date):
    if not re_birth_date.search(birth_date):
        return False
    try:
        import datetime
        datetime.datetime.strptime(birth_date, '%Y-%m-%d').date()
    except Exception:
        return False
    return True


# Редирект на домашнюю страницу
def redirect_to_home(request, response=None):
    if not response:
        response = Response()
    response.location = request.host_url
    response.status = '301 Moved'
    return response


# Генерируем id сессии
def create_session_id():
    return hashlib.sha224(os.urandom(56)).hexdigest()


# Авторизация, запись в сессию, ид сессии юзера из базы
def authorization(response, user):
    response.set_cookie('session_id', user.session_id)
    return response


# Проверка авторизован ли пользователь
# Если в cookie тот же session_id что и в базе, значит пользователь авторизован
def is_auth_user(environ):
    request = Request(environ)
    #user = None
    try:
        session_id = request.cookies['session_id']
        #db = Database()
        #user = db.get_user_from_session_id(session_id)
        user = get_user_from_session_id(session_id)
        return user
    except Exception:
        return None
    #return user


# Метод для отправки сообщений на емейл
def send_email(to_addr, subject, message):
    # Формируем сообщение
    msg = "From: {}\nTo: {}\nSubject: {}\n\n{}".format(settings.FROM_EMAIL,
                                                       to_addr,
                                                       subject, message)

    # Отправляем сообщение
    smtp = SMTP_SSL()
    smtp.connect(settings.SMTP)
    smtp.login(settings.FROM_EMAIL_LOGIN, settings.FROM_EMAIL_PASSWORD)
    smtp.sendmail(settings.FROM_EMAIL, to_addr, msg)
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


"""
#Проверка капчи
def captcha_check(request):
    #return True
    secret = settings.RECAPTCHA_PRIVATE_KEY
    response = request.POST['g-recaptcha-response']
    remoteip = get_client_ip(request)
    if response == '':
        return False
    else:
        #Запрос в гугл за результатом
        result = get_captcha_result(secret, response, remoteip)
        try:
            #парсим ответ
            struct_result = json.loads(result)
        except Exception:
            return False
        else:
            print struct_result
            #проверяем
            if struct_result['success'] == True:
                return True
            else:
                return False

#IP юзера
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0] #[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

#Формируем и посылаем запрос к гуглу
def get_captcha_result(secret, response, remoteip):
    url = 'https://www.google.com/recaptcha/api/siteverify?'
    if settings.PROXY_ON:
        opener = connect_proxy()
    else:
        opener = urllib2.build_opener()
    data = [
        ('secret', secret),
        ('response', response),
        ('remoteip', remoteip)
    ]
    encode_data = urllib.urlencode(data)
    request = urllib2.Request(url + encode_data)
    try:
        result = opener.open(request)
    except Exception, e:
        return e
    else:
        success = result.read()
        return success
"""