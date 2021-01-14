import math
import re
from flask import Flask, request, render_template, jsonify, url_for, redirect, abort
from flask_restplus import Api, Resource, fields
from db.const import *
from db.dbi import *
from db.note import *
from db.user import *

app = Flask(__name__, static_url_path="")
dbi = DatabaseInterface()


#
# COMPLEMENTARY FUNCTIONS SECTION
#


def getPasswordEntropy(password):
    alphabetSize = 0
    # Small letters and space
    if re.search("[a-z ]+", password):
        alphabetSize += 27
    # Big letters
    if re.search("[A-Z]+", password):
        alphabetSize += 26
    # Digits
    if re.search("[0-9]+", password):
        alphabetSize += 10
    # Special characters
    if re.search("[!-/:-@[-`{-~]+", password):
        alphabetSize += 15 + 7 + 6 + 4
    if alphabetSize == 0:
        return 0
    return len(password) * math.log2(alphabetSize)


def sanitizeText(text):
    if type(text) is not str:
        return ""
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text


# TODO hotfix, think of something better
def mr(response, status_code):
    response.status_code = status_code
    return response


#
# SESSION SECTION
#


@app.before_request
def before_request():
    session_id = request.cookies.get(SESSION_ID_KEY)
    validation_result = dbi.validateSession(session_id)
    if validation_result:
        request.environ["secure_user_login"] = validation_result[0]
        request.environ["secure_session_id"] = session_id
        request.environ["secure_session_valid"] = True
        request.environ["secure_session_expiration_date"] = validation_result[1]
    else:
        request.environ["secure_session_id"] = session_id
        request.environ["secure_session_valid"] = False
        if request.path.startswith("/secure"):
            abort(401)


@app.after_request
def after_request(response):
    if request.environ["secure_session_valid"]:
        session_id = request.environ["secure_session_id"]
        session_expiration_date = request.environ[
            "secure_session_expiration_date"]
        response.set_cookie(SESSION_ID_KEY, session_id,
                            expires=session_expiration_date,
                            secure=True, httponly=True)
    return response


#
# WEBSITE SECTION
#


@app.route("/", methods=[GET])
def homePage():
    return redirect(url_for("logInPage"))


@app.route("/log-in", methods=[GET])
def logInPage():
    return render_template("log-in.html")


@app.route("/register", methods=[GET])
def registerPage():
    return render_template("register.html")


@app.route("/reset-password", methods=[GET])
def resetPasswordPage():
    token = sanitizeText(request.args.get("token"))
    if token:
        return render_template("reset-password-token.html", token=token)
    return render_template("reset-password.html")


@app.route("/note/<code>", methods=[GET])
def notePage(code):
    if request.environ["secure_session_valid"]:
        return redirect(url_for("secureNotePage", code=code))
    if not dbi.doesNoteExist(code):
        return render_template("note-no-access.html")
    note = dbi.getNote(code)
    if dbi.validateUserReadAccessToNote(note.code):
        return render_template(
            "note-read-access.html",
            note_tile=note.title,
            note_description=note.description,
            note_url="seen.com{}".format(url_for("notePage", code=note.code)))
    return render_template("note-no-access.html")


@app.route("/secure", methods=[GET])
def securePage():
    return redirect(url_for("secureProfilePage"))


@app.route("/secure/user", methods=[GET])
def secureProfilePage():
    user_login = request.environ["secure_user_login"]
    user = dbi.getUser(user_login)
    return render_template(
        "secure-user.html",
        user_login=user.login,
        user_email=user.email,
        user_name=user.name,
        user_surname=user.surname)


@app.route("/secure/user/change-password", methods=[GET])
def secureChangePasswordPage():
    return render_template("secure-change-password.html")


@app.route("/secure/note", methods=[GET])
def secureNoteListPage():
    user_login = request.environ["secure_user_login"]
    note_list = dbi.getNoteList(user_login)
    return render_template("secure-note-list.html", note_list=note_list)


@app.route("/secure/note/<code>", methods=[GET])
def secureNotePage(code):
    if not dbi.doesNoteExist(code):
        return render_template("secure-note-no-access.html")
    note = dbi.getNote(code)
    user_login = request.environ["secure_user_login"]
    if dbi.validateUserWriteAccessToNote(note.code, user_login):
        note_authorized_users_text = ""
        for user in note.authorized_users:
            note_authorized_users_text += "{}, ".format(user)
        if note_authorized_users_text:
            note_authorized_users_text = note_authorized_users_text[:-2]
        return render_template(
            "secure-note-write-access.html",
            note_code=note.code,
            note_title=note.title,
            note_description=note.description,
            note_authorized_users_text=note_authorized_users_text,
            note_is_public=note.is_public,
            note_url="seen.com{}".format(url_for("notePage", code=note.code)))
    if dbi.validateUserReadAccessToNote(note.code, user_login):
        return render_template(
            "secure-note-read-access.html",
            note_tile=note.title,
            note_description=note.description,
            note_url="seen.com{}".format(url_for("notePage", code=note.code)))
    return render_template("secure-note-no-access.html")


@app.route("/secure/log-out", methods=[GET])
def logoutPage():
    return render_template("secure-log-out.html")


#
# API SECTION
#


@property
def specs_url(self):
    """ Monkey patch for HTTPS """
    return "https://seen.com/swagger.json"


Api.specs_url = specs_url
api = Api(app, doc="/api")

user_namespace = api.namespace(
    "User",
    path="/api/user",
    description="User Service API")

note_namespace = api.namespace(
    "Note",
    path="/api/note",
    description="Note Service API")


@user_namespace.route("/log-in")
class LoginResource(Resource):

    log_in_form_model = api.model("Log In Form Model", {
        "login": fields.String(
            required=True, description="A login."),
        "password": fields.String(
            required=True, description="A password.")})

    @api.expect(log_in_form_model)
    @api.doc(responses={200: "OK",
                        401: "Unauthorized, {error_message: string}"})
    def post(self):
        """ Logs in a user. """
        request_error = self.__validateLoginRequest(request)
        if request_error:
            return mr(jsonify(error_message=request_error), 401)
        login = request.form.get("login")
        session_id, expiration_date = dbi.createSession(login)
        response = mr(jsonify(redirect_url=url_for("securePage")), 200)
        response.set_cookie(SESSION_ID_KEY, session_id,
                            expires=expiration_date,
                            secure=True, httponly=True)
        return response

    def __validateLoginRequest(self, request):
        login = request.form.get("login")
        password = request.form.get("password")
        if not login:
            return "The login must not be empty."
        if not password:
            return "The password must not be empty."
        dbi.delayLogin(login)
        if not dbi.doesUserExist(login):
            dbi.recordLoginAttempt(login, False)
            return "The login or password is invalid."
        if not dbi.validateUser(login, password):
            dbi.recordLoginAttempt(login, False)
            return "The login or password is invalid."
        dbi.recordLoginAttempt(login, True)
        return None


@user_namespace.route("/log-out")
class LogoutResource(Resource):

    @api.doc(responses={200: "OK",
                        401: "Unauthorized, {error_message: string}"})
    def post(self):
        """ Logs out a user. """
        if not request.environ["secure_session_valid"]:
            return mr(jsonify(error_message="The session is invalid."), 401)
        session_id = request.environ["secure_session_id"]
        if not dbi.destroySession(session_id):
            return mr(jsonify(error_message="Could not destroy the session "
                              "(ID: {}).".format(session_id)), 500)
        request.environ["secure_session_id"] = ""
        request.environ["secure_session_expiration_date"] = 0
        return mr(jsonify(redirect_url=url_for("logInPage")), 200)


@user_namespace.route("/register")
class RegisterResource(Resource):

    register_form_model = api.model("Register Form Model", {
        "login": fields.String(required=True, description="A login."),
        "password": fields.String(required=True, description="A password."),
        "password_repetition": fields.String(
            required=True, description="A password repetition."),
        "email": fields.String(required=True, description="An email."),
        "name": fields.String(required=True, description="A name."),
        "surname": fields.String(required=True, description="A surname.")})

    @api.expect(register_form_model)
    @api.doc(responses={201: "Created",
                        400: "Bad Request, {error_message: string}"})
    def post(self):
        """ Creates a new user. """
        request_error = self.__validateRegisterRequest(request)
        if request_error:
            return mr(jsonify(error_message=request_error), 400)
        login = request.form.get("login")
        if dbi.doesUserExist(login):
            return mr(jsonify(error_message="The user already exists (login: "
                              "{}).".format(login)), 400)
        self.__registerUserFromRequest(request)
        return mr(jsonify(redirect_url=url_for("logInPage")), 201)

    def __validateRegisterRequest(self, request):
        login = request.form.get("login")
        password = request.form.get("password")
        password_repetition = request.form.get("password_repetition")
        email = sanitizeText(request.form.get("email"))
        name = sanitizeText(request.form.get("name"))
        surname = sanitizeText(request.form.get("surname"))
        if not login:
            return "The login must not be empty."
        if not password:
            return "The password must not be empty."
        if not password_repetition:
            return "The password repetition must not be empty."
        if not email:
            return "The email must not be empty."
        if not name:
            return "The name must not be empty."
        if not surname:
            return "The surname must not be empty."
        if len(login) < 5:
            return "The login must consist of at least 5 characters."
        if not re.search("^[a-zA-Z]+$", login):
            return "The login may only constist of small and big letters of " \
                "the latin alphabet."
        if len(password) < 8:
            return "The password must consist of at least 8 characters."
        if not re.search(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%&*])(.*)$",
                password):
            return "The password must contain small and big letters, digits " \
                "and special characters (!@#$%&*)."
        password_entropy = getPasswordEntropy(password)
        if password_entropy < PASSWORD_MINIMAL_ENTROPY:
            return "The password's etropy is too low ({:.2f} bits). " \
                "At least {} bits of entropy are required.".format(
                    password_entropy, PASSWORD_MINIMAL_ENTROPY)
        if password != password_repetition:
            return "The password repetition does not match the original " \
                "password."
        # TODO regex validate email
        return None

    def __registerUserFromRequest(self, request):
        login = request.form.get("login")
        password = request.form.get("password")
        email = sanitizeText(request.form.get("email"))
        name = sanitizeText(request.form.get("name"))
        surname = sanitizeText(request.form.get("surname"))
        if not login:
            abort(500, "Could not register an user. The login must not "
                  "be empty.")
        if not password:
            abort(500, "Could not register an user. The password must not "
                  "be empty.")
        if dbi.doesUserExist(login):
            abort(500, "Could not register an user. The user already exists "
                  "(login: {}).".format(login))
        id = dbi.getUserIdFromLogin(login)
        login = login.lower()
        password_hash = dbi.hashPassword(password)
        user = User(
            id,
            login,
            password_hash,
            email,
            name,
            surname)
        user_validation_error = user.validate()
        if user_validation_error:
            abort(500,
                  "Could not register an user. The user is invalid. "
                  "{}".format(user_validation_error))
        dbi.getDatabase().set(user.id, user.toData())


@user_namespace.route("/password/change")
class ChangePasswordResource(Resource):

    @api.doc()
    def post(self):
        """ Changes a user's password. """
        if not request.environ["secure_session_valid"]:
            return mr(jsonify(error_message="The session is invalid."), 401)
        user_login = request.environ["secure_user_login"]
        request_error = self.__validateChangePasswordRequest(request)
        if request_error:
            return mr(jsonify(error_message=request_error), 400)
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        if not dbi.validateUser(user_login, old_password):
            return mr(jsonify(
                error_message="The old password is invalid."), 401)
        dbi.changePassword(user_login, old_password, new_password)
        return "OK", 200

    def __validateChangePasswordRequest(self, request):
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        new_password_repetition = request.form.get("new_password_repetition")
        if not old_password:
            return "The old password must not be empty."
        if not new_password:
            return "The new password must not be empty."
        if not new_password_repetition:
            return "The new password repetition must not be empty."
        if len(new_password) < 8:
            return "The new password must consist of at least 8 characters."
        if not re.search(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%&*])(.*)$",
                new_password):
            return "The new password must contain small and big letters, " \
                "digits and special characters (!@#$%&*)."
        password_entropy = getPasswordEntropy(new_password)
        if password_entropy < PASSWORD_MINIMAL_ENTROPY:
            return "The new password's etropy is too low ({} bits). At least " \
                "{} bits of entropy are required.".format(
                    password_entropy, PASSWORD_MINIMAL_ENTROPY)
        if new_password != new_password_repetition:
            return "The password repetition does not match the original " \
                "password."
        return None


@user_namespace.route("/password/reset")
class ResetPasswordResource(Resource):

    @api.doc()
    def post(self):
        """ Resets a user's password. """
        request_error = self.__validateResetPasswordRequest(request)
        if request_error:
            return mr(jsonify(error_message=request_error), 400)
        token = request.form.get("token")
        if token:
            if not dbi.validatePasswordResetToken(token):
                return mr(jsonify(error_message="The password reset token "
                                  "is invalid."), 400)
            new_password = request.form.get("new_password")
            dbi.resetPassword(token, new_password)
        else:
            login = request.form.get("login")
            if not dbi.doesUserExist(login):
                return "OK", 200
            dbi.createAndSendPasswordResetToken(login)
        return "OK", 200

    def __validateResetPasswordRequest(self, request):
        token = request.form.get("token")
        if token:
            new_password = request.form.get("new_password")
            new_password_repetition = \
                request.form.get("new_password_repetition")
            if not new_password:
                return "The new password must not be empty."
            if not new_password_repetition:
                return "The new password repetition must not be empty."
            if len(new_password) < 8:
                return "The new password must consist of at least 8 characters."
            if not re.search(
                    "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%&*])(.*)$",
                    new_password):
                return "The new password must contain small and big letters, " \
                    "digits and special characters (!@#$%&*)."
            password_entropy = getPasswordEntropy(new_password)
            if password_entropy < PASSWORD_MINIMAL_ENTROPY:
                return "The new password's etropy is too low ({:.2f} bits). " \
                    "At least {} bits of entropy are required.".format(
                        password_entropy, PASSWORD_MINIMAL_ENTROPY)
            if new_password != new_password_repetition:
                return "The password repetition does not match the original " \
                    "password."
        else:
            login = request.form.get("login")
            if not login:
                return "The login must not be empty."
        return None


@note_namespace.route("")
class NoteListResource(Resource):

    # TODO def get (return list of notes)

    @api.doc()
    def post(self):
        """ Creates a new note. """
        if not request.environ["secure_session_valid"]:
            return mr(jsonify(error_message="The session is invalid."), 401)
        user_login = request.environ["secure_user_login"]
        user_id = dbi.getUserIdFromLogin(user_login)
        code = dbi.generateNoteCode()
        id = dbi.getNoteIdFromCode(code)
        note = Note(id, code, "New note", "", user_login, [], False)
        note_validation_error = note.validate()
        if note_validation_error:
            return mr(jsonify(error_message=note_validation_error), 400)
        dbi.getDatabase().set(note.id, note.toData())
        dbi.getDatabase().hset(NOTE_ID_TO_OWNER_ID_MAP, note.id, user_id)
        return mr(jsonify(
            redirect_url=url_for("secureNotePage", code=code)), 201)


@note_namespace.route("/<code>")
class NoteResource(Resource):

    # TODO def get (return a note)

    @api.doc()
    def put(self, code):
        """ Updates a note. """
        if not request.environ["secure_session_valid"]:
            return mr(jsonify(error_message="The session is invalid."), 401)
        user_login = request.environ["secure_user_login"]
        if not dbi.doesNoteExist(code):
            return mr(jsonify(error_message="The note does not exist or "
                              "the user does not have a write access to "
                              "the note (note_code: {}, user_login: "
                              "{}).".format(code, user_login)), 400)
        if not dbi.validateUserWriteAccessToNote(code, user_login):
            return mr(jsonify(error_message="The note does not exist or "
                              "the user does not have a write access to "
                              "the note (note_code: {}, user_login: "
                              "{}).".format(code, user_login)), 400)
        title = request.form.get("title")
        description = request.form.get("description")
        authorized_users = request.form.get("authorized_users")
        is_public = request.form.get("is_public")
        if title is not None:
            if not title:
                return mr(jsonify(error_message="The title must not "
                                  "be empty."), 400)
            title = sanitizeText(title)
        print(title, flush=True)
        if description is not None:
            description = sanitizeText(description)
        if authorized_users is not None:
            authorized_users = authorized_users.split(",")
            authorized_users[:] = [
                sanitizeText(user.lower().strip("[]").strip())
                for user in authorized_users]
        if is_public is not None:
            if is_public.lower() == "true":
                is_public = True
            else:
                is_public = False
        dbi.updateNote(code, title, description, authorized_users, is_public)
        return "OK", 200

    @api.doc()
    def delete(self, code):
        """ Deletes a note. """
        if not request.environ["secure_session_valid"]:
            return mr(jsonify(error_message="The session is invalid."), 401)
        user_login = request.environ["secure_user_login"]
        if not dbi.doesNoteExist(code):
            return mr(jsonify(error_message="The note does not exist or "
                              "the user does not have a write access to "
                              "the note (note_code: {}, user_login: "
                              "{}).".format(code, user_login)), 400)
        if not dbi.validateUserWriteAccessToNote(code, user_login):
            return mr(jsonify(error_message="The note does not exist or "
                              "the user does not have a write access to "
                              "the note (note_code: {}, user_login: "
                              "{}).".format(code, user_login)), 400)
        note_id = dbi.getNoteIdFromCode(code)
        dbi.getDatabase().delete(note_id)
        dbi.getDatabase().hdel(NOTE_ID_TO_OWNER_ID_MAP, note_id)
        return mr(jsonify(redirect_url=url_for("secureNoteListPage")), 200)
