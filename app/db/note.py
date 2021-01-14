import json


class Note:

    def __init__(self, id, code, title, description,
                 owner, authorized_users, is_public):
        self.id = id
        self.code = code
        self.title = title
        self.description = description
        self.owner = owner
        self.authorized_users = authorized_users
        self.is_public = is_public

    @classmethod
    def __loadFromJson(cls, data):
        return cls(**data)

    @classmethod
    def loadFromData(cls, data):
        return Note.__loadFromJson(json.loads(data))

    def toData(self):
        return json.dumps(self.__dict__)

    def validate(self):
        if not self.id:
            return "The ID must not be empty."
        if not self.code:
            return "The code must not be empty."
        if not self.title:
            return "The title must not be empty."
        if not self.owner:
            return "The owner must not be empty."
        if type(self.authorized_users) is not list:
            return "The authorized user list is invalid."
        if type(self.is_public) is not bool:
            return "The \"is_public\" flag is invalid."
        return None
