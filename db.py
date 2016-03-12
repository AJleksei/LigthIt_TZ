#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sqlite3


class User:
    id = None

    def __init__(self, id, lastName, firstName, login, password, email,
                 birthDate, mobilePhone, session_id):
        self.id = id
        self.lastName = lastName
        self.firstName = firstName
        self.login = login
        self.password = password
        self.email = email
        self.birthDate = birthDate
        self.mobilePhone = mobilePhone
        self.session_id = session_id


class Database:
    def create_db(self):
        try:
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            # Создание таблицы пользователей
            c.execute('''CREATE TABLE IF NOT EXISTS Users (
                          id INTEGER PRIMARY KEY,
                          lastName VARCHAR(30),
                          firstName VARCHAR(30),
                          login VARCHAR(30),
                          password VARCHAR(30),
                          email VARCHAR(30),
                          birthDate DATE,
                          mobilePhone VARCHAR(11),
                          session_id VARCHAR(56)
                        )
                    ''')

            # c.execute("INSERT INTO Users (id, lastName, firstName, login, password, email, birthDate,"
            #          "mobilePhone) VALUES(NULL, 'Попович', 'Алексей', 'AJleksei', '123456','AJleksei@ukr.net',"
            #          "'1991-08-02','099-9370673')")
            conn.commit()
            # Insert a row of data

        finally:
            # Закрываем соединение с БД в любом случае
            conn.close()

    def get_user_from_login(self, login):
        user = None
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            # Получаем пользователя по логину
            for user_db in c.execute(
                                    'SELECT DISTINCT * FROM Users WHERE login '
                                    'LIKE "' + login + '"'):
                user = User(user_db[0], user_db[1], user_db[2], user_db[3],
                            user_db[4], user_db[5], user_db[6], user_db[7],
                            user_db[8])
        finally:
            conn.close()
        return user

    def get_user_from_id(self, id):
        user = None
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            # Получаем пользователя по id
            for user_db in c.execute('SELECT DISTINCT * FROM Users WHERE id '
                                     '== "' + id + '"'):
                user = User(user_db[0], user_db[1], user_db[2], user_db[3],
                            user_db[4], user_db[5], user_db[6], user_db[7],
                            user_db[8])
        finally:
            conn.close()
        return user

    def get_user_from_session_id(self, session_id):
        user = None
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            # Получаем пользователя по id
            for user_db in c.execute('SELECT DISTINCT * FROM Users WHERE session_id '
                                     '== "' + session_id + '"'):
                user = User(user_db[0], user_db[1], user_db[2], user_db[3],
                            user_db[4], user_db[5], user_db[6], user_db[7],
                            user_db[8])
        finally:
            conn.close()
        return user

    def get_all_users(self):
        users = []
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            # Получаем пользователя по логину
            for user_db in c.execute('SELECT DISTINCT * FROM Users'):
                user = User(user_db[0], user_db[1], user_db[2], user_db[3],
                            user_db[4], user_db[5], user_db[6], user_db[7],
                            user_db[8])
                users.append(user)
        finally:
            conn.close()
        return users

    def add_user(self, user):
        user_new = None
        try:
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            user_new = c.execute(
                "INSERT INTO Users (id, lastName, firstName, login, password, email, birthDate,"
                "mobilePhone, session_id) VALUES(NULL, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user.lastName, user.firstName, user.login,
                 user.password, user.email, user.birthDate, user.mobilePhone,
                 user.session_id))
            conn.commit()
        finally:
            # Закрываем соединение с БД в любом случае
            conn.close()
        return user_new

    def edit_user(self, user):
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            user = c.execute(
                'UPDATE Users SET lastName = ?, firstName = ?, login = ?, password = ?, email = ?, '
                'birthDate = ?, mobilePhone = ?, session_id = ? WHERE id= ? ',
                (user.lastName, user.firstName, user.login, user.password,
                 user.email, user.birthDate, user.mobilePhone,
                 user.session_id, user.id))
            conn.commit()
        finally:
            conn.close()
        return user

    def delete_user_from_id(self, user_id):
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            c.execute('DELETE FROM Users WHERE id= ? ', user_id)
            conn.commit()
        finally:
            conn.close()
