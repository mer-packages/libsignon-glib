from ..overrides import override
from ..importer import modules
from gi.repository import GObject

Signon = modules['Signon']._introspection_module

__all__ = []

class GStrv(list):
    __gtype__ = GObject.type_from_name('GStrv')

class AuthSession(Signon.AuthSession):

    # Convert list of strings into a GStrv
    def process(self, session_data, mechanism, callback, userdata):
        cleaned_data = {}
        for (key, value) in session_data.items():
            if isinstance(value, list):
                cleaned_data[key] = GStrv(value)
            else:
                cleaned_data[key] = value
        Signon.AuthSession.process(self, cleaned_data, mechanism, callback, userdata)

AuthSession = override(AuthSession)
__all__.append('AuthSession')

