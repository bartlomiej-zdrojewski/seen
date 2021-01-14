import json


class User:

    def __init__(self, id, login, password_hash, email, name, surname):
        self.id = id
        self.login = login
        self.password_hash = password_hash
        self.email = email
        self.name = name
        self.surname = surname

    @classmethod
    def __loadFromJson(cls, data):
        return cls(**data)

    @classmethod
    def loadFromData(cls, data):
        return User.__loadFromJson(json.loads(data))

    def toData(self):
        return json.dumps(self.__dict__)

    def validate(self):
        if not self.id:
            return "The ID must not be empty."
        if not self.login:
            return "The login must not be empty."
        if not self.password_hash:
            return "The password hash must not be empty."
        if not self.email:
            return "The email must not be empty."
        # TODO regex validate email
        if not self.name:
            return "The name must not be empty."
        if not self.surname:
            return "The surname must not be empty."
        return None
