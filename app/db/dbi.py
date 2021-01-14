import os
import redis
import uuid
import base64
import dateutil.parser
from time import sleep
from datetime import datetime, timedelta
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from flask import abort
from .const import *
from .note import *
from .user import *


class DatabaseInterface:

    def __init__(self):
        salt = os.environ.get(SALT_KEY)
        if not salt:
            raise Exception("{} variable is not set.".format(SALT_KEY))
        self.db = redis.Redis(host="redis", port=6379, decode_responses=True)
        self.salt = base64.b64decode(salt)

    def getDatabase(self):
        return self.db

    def sendEmail(self, address, title, content):
        with open("email.txt", "a") as file:
            file.write("{}\n{}\n{}\n\n".format(address, title, content))

    #
    # USER SECTION
    #

    def getUserIdFromLogin(self, login):
        return USER_PREFIX + login.lower()

    def doesUserExist(self, login):
        if not login:
            return False
        return self.db.exists(self.getUserIdFromLogin(login))

    def getUser(self, login):
        if not self.doesUserExist(login):
            abort(500, "Could not get the user. The user does not exist "
                  "(login: {}).".format(login))
        user_id = self.getUserIdFromLogin(login)
        return User.loadFromData(self.db.get(user_id))

    def validateUser(self, login, password):
        if not self.doesUserExist(login):
            return False
        user = self.getUser(login)
        password_hash = self.hashPassword(password)
        if password_hash != user.password_hash:
            return False
        return True

    #
    # NOTE SECTION
    #

    def generateNoteCode(self):
        return str(uuid.uuid4()).replace("-", "")

    def getNoteIdFromCode(self, code):
        return NOTE_PREFIX + code.lower()

    def doesNoteExist(self, code):
        if not code:
            return False
        return self.db.exists(self.getNoteIdFromCode(code))

    def getNote(self, code):
        if not self.doesNoteExist(code):
            abort(500, "Could not get the note. The note does not exist "
                  "(code: {}).".format(code))
        note_id = self.getNoteIdFromCode(code)
        return Note.loadFromData(self.db.get(note_id))

    def getNoteList(self, user_login):
        note_list = []
        user_id = self.getUserIdFromLogin(user_login)
        for note_id in self.db.hkeys(NOTE_ID_TO_OWNER_ID):
            if user_id == self.db.hget(NOTE_ID_TO_OWNER_ID, note_id):
                if not self.db.exists(note_id):
                    abort(500,
                          "Could not get the note list. One of the notes "
                          "does not exist (note_id: "
                          "{}).".format(note_id))
                note = Note.loadFromData(self.db.get(note_id))
                note_list.append({
                    "title": note.title,
                    "description": note.description,
                    "url": "/secure/note/" + note.code})
        return note_list

    def updateNote(self, code, title, description, authorized_users, is_public):
        if not self.doesNoteExist(code):
            abort(500, "Could not update the note. The note does not exist "
                  "(code: {}).".format(code))
        note = self.getNote(code)
        if title is not None:
            note.title = title
        if description is not None:
            note.description = description
        if authorized_users is not None:
            note.authorized_users = authorized_users
        if is_public is not None:
            note.is_public = is_public
        note_validation_error = note.validate()
        if note_validation_error:
            abort(500, "Could not update the note. The note is invalid. "
                  "{}".format(note_validation_error))
        self.db.set(note.id, note.toData())

    def validateUserReadAccessToNote(self, note_code, user_login=None):
        if not self.doesNoteExist(note_code):
            abort(500, "Could not validate user's read access to the note. "
                  "The note does not exist (note_code: {}).".format(note_code))
        note = self.getNote(note_code)
        if note.is_public:
            return True
        if user_login:
            if not self.doesUserExist(user_login):
                abort(500, "Could not validate user's read access to the note. "
                      "The user does not exist (user_login: {}).".format(
                          user_login))
            if user_login == note.owner:
                return True
            if user_login in note.authorized_users:
                return True
        return False

    def validateUserWriteAccessToNote(self, note_code, user_login=None):
        if not self.doesNoteExist(note_code):
            abort(500, "Could not validate user's write access to the note. "
                  "The note does not exist (note_code: {}).".format(note_code))
        note = self.getNote(note_code)
        if user_login:
            if not self.doesUserExist(user_login):
                abort(500, "Could not validate user's write access to "
                      "the note. The user does not exist (user_login: "
                      "{}).".format(user_login))
            if user_login == note.owner:
                return True
        return False

    #
    # LOGIN SECTION
    #

    def getLoginAttemptCount(self, login):
        login_attempt_count = 0
        if self.db.hexists(LOGIN_TO_LOGIN_ATTEMPT_COUNT_MAP, login):
            login_attempt_count = \
                self.db.hget(LOGIN_TO_LOGIN_ATTEMPT_COUNT_MAP, login)
        return int(login_attempt_count)

    def recordLoginAttempt(self, login, successful):
        login_attempt_count = self.getLoginAttemptCount(login)
        if successful:
            login_attempt_count = 0
        else:
            login_attempt_count += 1
        self.db.hset(LOGIN_TO_LOGIN_ATTEMPT_COUNT_MAP,
                     login, login_attempt_count)
        # TODO record IP address

    def delayLogin(self, login):
        delay_seconds = 10
        login_attempt_count = self.getLoginAttemptCount(login)
        if (login_attempt_count >= 0 and login_attempt_count <= 5):
            delay_seconds = 0.2 * 2 ** login_attempt_count
        sleep(delay_seconds)

    #
    # PASSWORD SECTION
    #

    def hashPassword(self, password):
        return base64.b64encode(PBKDF2(password, self.salt, 16, count=1024,
                                       hmac_hash_module=SHA256)).decode()

    def changePassword(self, user_login, old_password, new_password):
        if not self.validateUser(user_login, old_password):
            return False
        user = self.getUser(user_login)
        user.password_hash = self.hashPassword(new_password)
        self.db.set(user.id, user.toData())
        return True

    def resetPassword(self, token, new_password):
        validation_result = self.validatePasswordResetToken(token)
        if not validation_result:
            abort(500, "The password reset token is invalid (token: "
                  "{}).".format(token))
        user_login = validation_result[0]
        user = self.getUser(user_login)
        user.password_hash = self.hashPassword(new_password)
        self.db.set(user.id, user.toData())
        if not self.destroyPasswordResetToken(token):
            abort(500, "Could not destroy the password reset token (token: "
                  "{}).".format(token))

    def createAndSendPasswordResetToken(self, user_login):
        if not self.doesUserExist(user_login):
            abort(500,
                  "Could not create a password reset token. The user does not "
                  "exist (user_login: {}).".format(user_login))
        token = str(uuid.uuid4()).replace("-", "")
        token_expiration_date = datetime.utcnow(
        ) + timedelta(seconds=PASSWORD_RESET_TOKEN_EXPIRATION_TIME)
        self.db.hset(
            PASSWORD_RESET_TOKEN_TO_USER_LOGIN_MAP,
            token, user_login)
        self.db.hset(
            PASSWORD_RESET_TOKEN_TO_PASSWORD_RESET_TOKEN_EXPIRATION_DATE_MAP,
            token, token_expiration_date.isoformat())
        user = self.getUser(user_login)
        email_address = user.email
        email_title = "A password reset token"
        email_content = "{}\nhttps://seen.com/reset-password?token={}".format(
            token, token)
        self.sendEmail(email_address, email_title, email_content)

    def validatePasswordResetToken(self, token):
        if not token:
            return None
        if not self.db.hexists(
                PASSWORD_RESET_TOKEN_TO_USER_LOGIN_MAP,
                token):
            return None
        if not self.db.hexists(
                PASSWORD_RESET_TOKEN_TO_PASSWORD_RESET_TOKEN_EXPIRATION_DATE_MAP,
                token):
            abort(500, "Could not validate the password reset token. "
                  "No expiration date match the token: {}.".format(token))
        token_expiration_date = dateutil.parser.parse(self.db.hget(
            PASSWORD_RESET_TOKEN_TO_PASSWORD_RESET_TOKEN_EXPIRATION_DATE_MAP,
            token))
        if token_expiration_date <= datetime.utcnow():
            if not self.destroyPasswordResetToken(token):
                abort(500, "Could not destroy the password reset token "
                      "(token: {}).".format(token))
            return None
        user_login = self.db.hget(
            PASSWORD_RESET_TOKEN_TO_USER_LOGIN_MAP, token)
        return (user_login, token_expiration_date)

    def destroyPasswordResetToken(self, token):
        if not self.db.hexists(PASSWORD_RESET_TOKEN_TO_USER_LOGIN_MAP, token):
            return False
        if not self.db.hexists(
                PASSWORD_RESET_TOKEN_TO_PASSWORD_RESET_TOKEN_EXPIRATION_DATE_MAP,
                token):
            return False
        self.db.hdel(PASSWORD_RESET_TOKEN_TO_USER_LOGIN_MAP, token)
        self.db.hdel(
            PASSWORD_RESET_TOKEN_TO_PASSWORD_RESET_TOKEN_EXPIRATION_DATE_MAP,
            token)
        return True

    #
    # SESSION SECTION
    #

    def createSession(self, user_login):
        if not self.doesUserExist(user_login):
            abort(500,
                  "Could not create a session. The user does not exist "
                  "(user_login: {}).".format(user_login))
        session_id = str(uuid.uuid4()).replace("-", "")
        session_expiration_date = datetime.utcnow(
        ) + timedelta(seconds=SESSION_EXPIRATION_TIME)
        self.db.hset(SESSION_ID_TO_USER_LOGIN_MAP, session_id, user_login)
        self.db.hset(SESSION_ID_TO_SESSION_EXPIRATION_DATE_MAP,
                     session_id, session_expiration_date.isoformat())
        return (session_id, session_expiration_date)

    def validateSession(self, session_id):
        if not session_id:
            return None
        if not self.db.hexists(SESSION_ID_TO_USER_LOGIN_MAP, session_id):
            return None
        if not self.db.hexists(SESSION_ID_TO_SESSION_EXPIRATION_DATE_MAP,
                               session_id):
            abort(500, "Could not validate the session. No expiration date "
                  "match the session ID: {}.".format(session_id))
        session_expiration_date = dateutil.parser.parse(self.db.hget(
            SESSION_ID_TO_SESSION_EXPIRATION_DATE_MAP, session_id))
        if session_expiration_date <= datetime.utcnow():
            if not self.destroySession(session_id):
                abort(500, "Could not destroy the session (ID: {}).".format(
                    session_id))
            return None
        session_expiration_date = datetime.utcnow(
        ) + timedelta(seconds=SESSION_EXPIRATION_TIME)
        self.db.hset(SESSION_ID_TO_SESSION_EXPIRATION_DATE_MAP,
                     session_id, session_expiration_date.isoformat())
        user_login = self.db.hget(SESSION_ID_TO_USER_LOGIN_MAP, session_id)
        return (user_login, session_expiration_date)

    def destroySession(self, session_id):
        if not self.db.hexists(SESSION_ID_TO_USER_LOGIN_MAP, session_id):
            return False
        if not self.db.hexists(SESSION_ID_TO_SESSION_EXPIRATION_DATE_MAP,
                               session_id):
            return False
        self.db.hdel(SESSION_ID_TO_USER_LOGIN_MAP, session_id)
        self.db.hdel(SESSION_ID_TO_SESSION_EXPIRATION_DATE_MAP, session_id)
        return True
