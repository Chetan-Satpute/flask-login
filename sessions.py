import os
from datetime import datetime
from uuid import uuid4

import pickle

from flask.sessions import SessionInterface as FlaskSessionInterface
from flask.sessions import SessionMixin
from werkzeug.datastructures import CallbackDict
from itsdangerous import Signer, BadSignature, want_bytes

text_type = str


def total_seconds(td):
    return td.days * 60 * 60 * 24 + td.seconds


class ServerSideSession(CallbackDict, SessionMixin):
    """Baseclass for server-side based sessions."""

    def __init__(self, initial=None, sid=None, permanent=None):
        def on_update(self):
            self.modified = True

        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        if permanent:
            self.permanent = permanent
        self.modified = False


class MongoDBSession(ServerSideSession):
    pass


class SessionInterface(FlaskSessionInterface):
    def _generate_sid(self):
        return str(uuid4())

    def _get_signer(self, app):
        if not hasattr(app, "secret_key") or not app.secret_key:
            raise KeyError(
                "SECRET_KEY must be set when SESSION_USE_SIGNER=True")
        return Signer(app.secret_key, salt="flask-session", key_derivation="hmac")

    def _unsign(self, app, sid):
        signer = self._get_signer(app)
        sid_as_bytes = signer.unsign(sid)
        sid = sid_as_bytes.decode()
        return sid

    def _sign(self, app, sid):
        signer = self._get_signer(app)
        sid_as_bytes = want_bytes(sid)
        return signer.sign(sid_as_bytes).decode("utf-8")


class MongoDBSessionInterface(SessionInterface):
    """A Session interface that uses mongodb as backend.

    .. versionadded:: 0.2
        The `use_signer` parameter was added.

    :param client: A ``pymongo.MongoClient`` instance.
    :param db: The database you want to use.
    :param collection: The collection you want to use.
    :param key_prefix: A prefix that is added to all MongoDB store keys.
    :param use_signer: Whether to sign the session id cookie or not.
    :param permanent: Whether to use permanent session or not.
    """

    serializer = pickle
    session_class = MongoDBSession

    def __init__(
        self, client, db, collection, key_prefix, use_signer=False, permanent=True
    ):
        if client is None:
            from pymongo import MongoClient

            client = MongoClient()
        self.client = client
        self.store = client[db][collection]
        self.key_prefix = key_prefix
        self.use_signer = use_signer
        self.permanent = permanent
        self.has_same_site_capability = hasattr(self, "get_cookie_samesite")

    def open_session(self, app, request):
        sid = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        if not sid:
            sid = self._generate_sid()
            return self.session_class(sid=sid, permanent=self.permanent)
        if self.use_signer:
            try:
                sid = self._unsign(app, sid)
            except BadSignature:
                sid = self._generate_sid()
                return self.session_class(sid=sid, permanent=self.permanent)

        store_id = self.key_prefix + sid
        document = self.store.find_one({"id": store_id})
        if document and document.get("expiration") <= datetime.utcnow():
            # Delete expired session
            self.store.delete_many({"id": store_id})
            document = None
        if document is not None:
            try:
                val = document["val"]
                data = self.serializer.loads(want_bytes(val))
                return self.session_class(data, sid=sid)
            except:
                return self.session_class(sid=sid, permanent=self.permanent)
        return self.session_class(sid=sid, permanent=self.permanent)

    def save_session(self, app, session: ServerSideSession, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        store_id = self.key_prefix + session.sid
        if not session:
            if session.modified:
                self.store.delete_many({"id": store_id})
                response.delete_cookie(
                    app.config["SESSION_COOKIE_NAME"], domain=domain, path=path
                )
            return

        conditional_cookie_kwargs = {}
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        if self.has_same_site_capability:
            conditional_cookie_kwargs["samesite"] = self.get_cookie_samesite(
                app)
        expires = self.get_expiration_time(app, session)
        val = self.serializer.dumps(dict(session))
        self.store.update_one(
            {"id": store_id},
            {"$set": {"id": store_id, "val": val, "expiration": expires}},
            upsert=True
        )
        if self.use_signer:
            session_id = self._sign(app, session.sid)
        else:
            session_id = session.sid

        if session_id:
            response.set_cookie(
                app.config["SESSION_COOKIE_NAME"],
                session_id,
                expires=expires,
                httponly=httponly,
                domain=domain,
                path=path,
                secure=secure,
                **conditional_cookie_kwargs,
            )


class Session(object):
    """This class is used to add Server-side Session to one or more Flask
    applications.

    There are two usage modes.  One is initialize the instance with a very
    specific Flask application::

        app = Flask(__name__)
        Session(app)

    The second possibility is to create the object once and configure the
    application later::

        sess = Session()

        def create_app():
            app = Flask(__name__)
            sess.init_app(app)
            return app

    By default Flask-Session will use :class:`NullSessionInterface`, you
    really should configurate your app to use a different SessionInterface.

    .. note::

        You can not use ``Session`` instance directly, what ``Session`` does
        is just change the :attr:`~flask.Flask.session_interface` attribute on
        your Flask applications.
    """

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """This is used to set up session for your app object.

        :param app: the Flask app object with proper configuration.
        """
        app.session_interface = self._get_interface(app)

    def _get_interface(self, app):
        config = app.config.copy()
        config.setdefault("SESSION_TYPE", "null")
        config.setdefault("SESSION_PERMANENT", True)
        config.setdefault("SESSION_USE_SIGNER", False)
        config.setdefault("SESSION_KEY_PREFIX", "session:")
        config.setdefault("SESSION_REDIS", None)
        config.setdefault("SESSION_MEMCACHED", None)
        config.setdefault(
            "SESSION_FILE_DIR", os.path.join(os.getcwd(), "flask_session")
        )
        config.setdefault("SESSION_FILE_THRESHOLD", 500)
        config.setdefault("SESSION_FILE_MODE", 384)
        config.setdefault("SESSION_MONGODB", None)
        config.setdefault("SESSION_MONGODB_DB", "flask_session")
        config.setdefault("SESSION_MONGODB_COLLECT", "sessions")
        config.setdefault("SESSION_SQLALCHEMY", None)
        config.setdefault("SESSION_SQLALCHEMY_TABLE", "sessions")

        session_interface = MongoDBSessionInterface(
            config["SESSION_MONGODB"],
            config["SESSION_MONGODB_DB"],
            config["SESSION_MONGODB_COLLECT"],
            config["SESSION_KEY_PREFIX"],
            config["SESSION_USE_SIGNER"],
            config["SESSION_PERMANENT"],
        )

        return session_interface
