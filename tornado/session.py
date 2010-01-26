# -*- coding: utf-8 -*-

"""
Sessions module for the Tornado framework.
Milan Cermak <milan.cermak@gmail.com> 

This module implements sessions for Tornado. So far, it can store
session data only in files or MySQL databse (Memcached and MongoDB
based are planned for future versions).

Every session object can be handled as a dictionary:
    self.session[key] = value
    var = self.session[key]

Unfortunately, for now, you have to explicitly save the session
if the sessin data has been updated. This will be fixed in the
near future.

Two utility functions, invalidate() and refresh() are available to
every session object. Read their documentation to learn more.

The application provider is responsible for removing stale, expired
sessions from the storage.

The session module introduces new settings available to the
application:

session_age: how long should the session be valid (applies also to cookies);
             the value can be anything, which is convertible to integer (number,
             string, datetime, timedelta, function, if none of these, uses
             None as default; for more info, look at _value_to_epoch_time() in
             BaseSession class)
             default is None, which means the cookie expires on browser close
             and lasts 30 mins on the server
session_cookie_name: the name of the cookie, which stores the session_id;
                     default is 'session_id'
session_cookie_path: path attribute for the session cookie;
                     default is '/'
session_cookie_domain: domain attribute for the session cookie;
                       default is None
session_storage: a string specifying the session storage;
                 only two storage engines are available at the moment, file
                 or MySQL based

                 if you want to store session data in a file, set this to
                 a url of the following format:
                 'file:///path/to/session_storage_file'
                 be sure the Tornado process has read & write access to this
                 file

                 if you want to use MySQL, set it in this format:
                 'mysql://username:password[@hostname[:port]]/database'

                 if you don't specify any storage, the default behaviour is
                 to create a new temporary file according to yours OS'
                 conventions (on Unix-like systems in the /tmp directory);
                 the file will have 'tornado_sessions_' as name prefix
session_security_model: not implemented yet;
                        the plan to future versions is to provide some basic
                        mechanisms to prevent session hijacking, based on
                        users IP address, User-Agent, GeoIP or whatever
                        other data; suggestions welcomed


              
"""

import base64
import csv
import collections
import datetime
import os
import cPickle as pickle
import re
import tempfile
import time
import types


class BaseSession(collections.MutableMapping):
    """The base class for the session object. Work with the session object
    is really simple, just treat is as any other dictionary:

    class Handler(tornado.web.RequestHandler):
        def get(self):
            var = self.session['key']
            self.session['another_key'] = 'value'
            self.session.save()

    (Unfortunately, for now, you have to explicitly call session.save().
    This will be fixed in a later revision.)

    You can also access the following attributes:
        session_id - a unique, random string identifier of the session,
                     stored in the user's cookie
        security_model - not implemented yet; a planned feature to prevent
                         (or at least make more difficult) session hijacking
        expires - timestamp (in sec since epoch) when the session will expire        
        
    To create a new storage system for the sessions, subclass BaseSession
    and define save(), load(), delete(), serialize() and deserialize().
    For inspiration, check out the FileSession or MySQLSession class."""
    def __init__(self, session_id=None, data=None, security_model=[], expires=None,
                 ip_address=None, user_agent=None, **kwargs):
        if session_id:
            self.session_id = session_id
        else:
            self.session_id = self._generate_session_id()
        self.data = data or {}
        self.expires = self._value_to_epoch_time(expires)
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.security_model = security_model
        self._delete_cookie_action = None
        self._refresh_cookie_action = None
        self.dirty = False

    def _set_cookie_actions(self, delete, refresh):
        self._delete_cookie_action = delete
        self._refresh_cookie_action = refresh

    def __repr__(self):
        return '<session id: %s data: %s>' % (self.session_id, self.data)

    def __str__(self):
        return self.session_id

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value
        self.dirty = True
        # TODO: if dirty, save automagically (that should be done in web.py, probably)

    def __delitem__(self, key):
        del self.data[key]
        self.dirty = True

    def keys(self):
        return self.data.keys()

    def __iter__(self):
        return self.data.__iter__()

    def __len__(self):
        return len(seld.data.keys())

    @classmethod
    def _generate_session_id(cls):
        return os.urandom(16).encode('hex') # 128 bits of entropy

    @classmethod
    def _value_to_epoch_time(self, value=None):
        # convert whatever value to time since epoch
        if isinstance(value, (int, long)):
            then = datetime.datetime.now() + datetime.timedelta(seconds=value)
            return int(time.mktime(then.timetuple()))
        elif isinstance(value, basestring):
            then = datetime.datetime.now() + datetime.timedelta(seconds=int(value))
            return int(time.mktime(then.timetuple()))
        elif isinstance(value, datetime.datetime):
            return int(time.mktime(value.timetuple()))
        elif isinstance(value, datetime.timedelta):
            then = datetime.datetime.now() + value
            return int(time.mktime(then.timetuple()))
        elif type(value) is types.FunctionType:
            return value()
        else:
            then = datetime.datetime.now() + datetime.timedelta(seconds=1800) # 30 mins
            return time.mktime(then.timetuple())

    def invalidate(self): 
        """Destorys the session, both server-side and client-side.
        As a best practice, it should be used when the user logs out of
        the application."""
        self.delete() # remove server-side
        self._delete_cookie_action() # remove client-side
    
    def refresh(self, to_time=None, new_session_id=False, save=True): # the oposite of invalidate
        """Prolongs the session validity. You can specify for how long passing a
        value in the to_time argument (the same rules as for session_age apply).
        
        If new_session_id is True, a new session identifier will be generated.
        This should be used e.g. on user authentication for security reasons.

        If you don't want to save the session server-side, only update the
        browser's cookie, pass save=False when calling the function."""
        self.expires = self._value_to_epoch_time(to_time)
        if new_session_id:
            self.delete()
            self.session_id = self._generate_session_id()
        if new_session_id or save:
            self.save() # store server-side
        self._refresh_cookie_action(self.session_id,
                                    expires=datetime.datetime.fromtimestamp(self.expires)) # store client-side

    def save(self):
        # TODO: should also refresh the expiry on save (?)
        pass

    @staticmethod
    def load(session_id, location):
        # the function should load a stored session, creating a new clean
        # one is a fail-save branch
        pass

    def delete(self): # remove only from the backend storage
        pass

    def serialize(self):
        pass

    @staticmethod
    def deserialize(datastring):
        pass


class FileSession(BaseSession):
    """File based session storage. Sessions are stored in CSV format. The file
    is either specified in the session_storage setting (be sure it is writable
    to the Tornado process) or a new tempfile with 'tornado_sessions_' prefix
    is created in the OS' standard location.
    
    Be aware that file-based sessions can get really slow with many stored
    session as any save() or delete() action has to cycle through the whole
    file. """
    def __init__(self, file_path, **kwargs):
        super(FileSession, self).__init__(**kwargs)
        self.file_path = file_path
        if not kwargs.has_key('session_id'):
            self.save() # save only if it is a newly created session, not if loaded from storage

    def save(self):
        """Save the session. To prevent data loss, we read from the original
        file and write the updated data to a temporary file. When all data is
        written, we rename the temporary file to the original. """
        found = False
        reader_file = open(self.file_path, 'rb')
        reader = csv.DictReader(reader_file,
                                fieldnames=['session_id', 'data', 'expires', 'ip_address', 'user-agent'])
        writer_temp = tempfile.mkstemp()[1]
        writer_temp_file = open(writer_temp, 'w+b')
        writer = csv.DictWriter(writer_temp_file,
                                ['session_id', 'data', 'expires', 'ip_address', 'user-agent'])
        for line in reader:
            if line['session_id'] == self.session_id:
                writer.writerow({'session_id': self.session_id,
                                 'data': self.serialize(),
                                 'expires': self.expires,
                                 'ip_address': self.ip_address,
                                 'user-agent': self.user_agent})
                found = True
            else:
                writer.writerow(line)

        if not found: # not previously stored session
            # column data will contain the whole object, not just the
            # data attribute
            writer.writerow({'session_id': self.session_id,
                             'data': self.serialize(),
                             'expires': self.expires,
                             'ip_address': self.ip_address,
                             'user-agent': self.user_agent})
        reader_file.close()
        writer_temp_file.close()
        os.rename(writer_temp, self.file_path)
        self.dirty = False

    @staticmethod
    def load(session_id, path):
        """Loads a session from the specified file. If the session doesn't
        exist anymore, the function returns a new, clean one. In either case
        it returns a FileSession instance."""
        reader_file = open(path, 'rb')
        reader = csv.DictReader(reader_file,
                                fieldnames=['session_id', 'data', 'expires', 'ip_address', 'user-agent'])
        for line in reader:
            if line['session_id'] == session_id:
                reader_file.close()                
                return FileSession.deserialize(line['data'])
        reader_file.close()
        return FileSession(path) # return empty session when bad ID

    def delete(self):
        """Remove the session from the storage file. File manipulation is
        done the same way as in save()."""
        reader_file = open(self.file_path, 'rb')
        reader = csv.DictReader(reader_file,
                                fieldnames=['session_id', 'data', 'expires', 'ip_address', 'user-agent'])
        writer_temp = tempfile.mkstemp()[1] 
        writer_temp_file = open(writer_temp, 'w+b')
        writer = csv.DictWriter(writer_temp_file,
                                ['session_id', 'data', 'expires', 'ip_address', 'user-agent'])
        for line in reader:
            if line['session_id'] != self.session_id:
                writer.writerow(line)

        reader_file.close()
        writer_temp_file.close()
        os.rename(writer_temp, self.file_path) # rename the temporary holder to the session file

    def serialize(self):
        dump = {'session_id': self.session_id,
                'data': self.data,
                'expires': self.expires,
                'ip_address': self.ip_address,
                'user_agent': self.user_agent,
                'security_model': self.security_model,
                'file_path': self.file_path}
        return base64.encodestring(pickle.dumps(dump))        

    @staticmethod
    def deserialize(datastring):
        load = pickle.loads(base64.decodestring(datastring))
        file_path = load.pop('file_path')
        return FileSession(file_path, **load)

                
class MySQLSession(BaseSession):
    """Enables MySQL to act as a session storage engine. It uses Tornado's
    MySQL wrapper from database.py.

    The connection details are specified in the session_storage settings
    as string mysql://username:password[@hostname[:port]]/database. It
    stores session data in the table tornado_sessions. If hostname or
    port aren't specified, localhost:3306 are used as defaults. """

    def __init__(self, connection, **kwargs):
        super(MySQLSession, self).__init__(**kwargs)
        self.connection = connection
        if not kwargs.has_key('session_id'):
            self.save()

    @classmethod
    def _parse_connection_details(cls, details):
        # mysql://username:password[@hostname[:port]]/db

        if details.find('@') != -1:
            match = re.match('mysql://(\w+):(.*?)@([\w|\.]+)(?::(\d+))?/(\S+)', details)
            username = match.group(1)
            password = match.group(2)
            hostname = match.group(3)
            port = match.group(4) or '3306'
            database = match.group(5)
            host_port = hostname + ':' + port
        else: # hostname and port not specified
            host_port = 'localhost:3306'
            match = re.match('mysql://(\w+):(.*?)/(\S+)', details)
            username = match.group(1)
            password = match.group(2)
            database = match.group(3)        

        return username, password, host_port, database

    def save(self):
        """Store the session data to database. If the table 'tornado_sessions'
        does not exist yet, create it. MySQL replace method is used to insert
        and update data."""
        if not self.connection.get("""show tables like 'tornado_sessions'"""):
            self.connection.execute( # create table if it doesn't exist
                """create table tornado_sessions (
                session_id varchar(64) not null primary key,
                data longtext,
                expires integer,
                ip_address varchar(46),
                user_agent varchar(255)
                );""")
        self.connection.execute( # MySQL's almost-upsert
            """replace tornado_sessions
            (session_id, data, expires, ip_address, user_agent)
            values(%s, %s, %s, %s, %s);""",
            self.session_id, self.serialize(), self.expires, self.ip_address,
            self.user_agent)
        self.dirty = False

    @staticmethod
    def load(session_id, connection):
        """Load stored session or return a new, clean one if the old no longer
        exist in the database."""
        data = connection.get("""
        select session_id, data, expires, ip_address, user_agent
        from tornado_sessions where session_id = %s;""",  session_id)
        if data:
            return MySQLSession.deserialize(data['data'], connection)
        else:
            return MySQLSession(connection)

    def delete(self):
        """Remove session data from the database."""
        self.connection.execute("""
        delete from tornado_sessions where session_id = %s;""", self.session_id)

    def serialize(self):
        dump = {'session_id': self.session_id,
                'data': self.data,
                'expires': self.expires,
                'ip_address': self.ip_address,
                'user_agent': self.user_agent,
                'security_model': self.security_model}
        return base64.encodestring(pickle.dumps(dump))

    @staticmethod
    def deserialize(datastring, connection):
        load = pickle.loads(base64.decodestring(datastring))
        return MySQLSession(connection, **load)


# possible future engines for session storage
class MemcachedSession(BaseSession):
    pass

class MongoDBSession(BaseSession):
    pass
