from flask import Flask
from flask_restplus import Api

app = Flask(__name__, static_url_path="")

@app.route("/", methods=["GET"])
def homePage():
    return "OK", 200

api = Api(app, doc="/api")
