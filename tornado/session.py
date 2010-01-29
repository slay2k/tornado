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

The session data is saved automatically for you when the request
handler finishes. 

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
             default is 15 mins
session_cookie_name: the name of the cookie, which stores the session_id;
                     default is 'session_id'
session_cookie_path: path attribute for the session cookie;
                     default is '/'
session_cookie_domain: domain attribute for the session cookie;
                       default is None
session_storage: a string specifying the session storage;
                 only two storage engines are available at the moment, file
                 or MySQL based

                 if you want to store session data in a single file, set
                 this to a url of the following format:
                 'file:///path/to/session_storage_file'

                 another choice is to store session in a directory, where
                 each session is stored in a separate, single file; to
                 enable this behaviour, set this setting to:
                 dir:///path/to/session/storage/directory
                 each session will be mapped to a file following the
                 <session_id>.session format, saved in this directory

                 be sure the Tornado process has read & write access to
                 this path, whether it's a file or a directory

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
import database
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
        # if session_id is True, we're loading a previously initialized session
        if session_id:
            self.session_id = session_id
            self.data = data
            self.expires = expires
            self.dirty = False
        else:
            self.session_id = self._generate_session_id()
            self.data = {}
            self.expires = self._value_to_epoch_time(expires)
            self.dirty = True

        self.ip_address = ip_address
        self.user_agent = user_agent
        self.security_model = security_model
        self._delete_cookie = False
        self._refresh_cookie = False

    def __repr__(self):
        return '<session id: %s data: %s>' % (self.session_id, self.data)

    def __str__(self):
        return self.session_id

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value
        self.dirty = True

    def __delitem__(self, key):
        del self.data[key]
        self.dirty = True

    def keys(self):
        return self.data.keys()

    def __iter__(self):
        return self.data.__iter__()

    def __len__(self):
        return len(self.data.keys())

    @classmethod
    def _generate_session_id(cls):
        return os.urandom(32).encode('hex') # 256 bits of entropy

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
            then = datetime.datetime.now() + datetime.timedelta(seconds=900) # 15 mins
            return int(time.mktime(then.timetuple()))

    def invalidate(self): 
        """Destorys the session, both server-side and client-side.
        As a best practice, it should be used when the user logs out of
        the application."""
        self.delete() # remove server-side
        self._delete_cookie = True # remove client-side
    
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
            self.dirty = True # to force save
            self.save() # store server-side
        self._refresh_cookie = True # store client-side

    def save(self):
        """Save the session data and metadata to the backend storage
        if necessary (self.dirty == True). On successful save set
        dirty to False."""
        pass

    @staticmethod
    def load(session_id, location):
        """Load the stored session from storage backend or return
        None if the session was not found, in case of stale cookie."""
        pass

    def delete(self):
        """Remove all data representing the session from backend storage."""
        pass

    def serialize(self):
        dump = {'session_id': self.session_id,
                'data': self.data,
                'expires': self.expires,
                'ip_address': self.ip_address,
                'user_agent': self.user_agent,
                'security_model': self.security_model}
        return base64.encodestring(pickle.dumps(dump))

    @staticmethod
    def deserialize(datastring):
        return pickle.loads(base64.decodestring(datastring))


class FileSession(BaseSession):
    """File based session storage. Sessions are stored in CSV format. The file
    is either specified in the session_storage setting (be sure it is writable
    to the Tornado process) or a new tempfile with 'tornado_sessions_' prefix
    is created in the OS' standard location.
    
    Be aware that file-based sessions can get really slow with many stored
    session as any action (save, load, delete) has to cycle through the whole
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
        if not self.dirty:
            return
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
        """Loads a session from the specified file."""
        try:
            reader_file = open(path, 'rb')
            reader = csv.DictReader(reader_file,
                                    fieldnames=['session_id', 'data', 'expires', 'ip_address', 'user-agent'])
            for line in reader:
                if line['session_id'] == session_id:
                    reader_file.close()
                    kwargs = FileSession.deserialize(line['data'])
                    return FileSession(path, **kwargs)
            reader_file.close()
            return None
        except:
            return None

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


class DirSession(BaseSession):
    """A "directory" based session storage. Every session is stored in a
    separate file, so one file represents one session. The files are
    named as the session_id plus '.session' suffix. Data is stored in
    CSV format. Make sure the directory where the files are stored is
    readable and writtable to the Tornado process."""
    def __init__(self, dir_path, **kwargs):
        super(DirSession, self).__init__(**kwargs)
        self.dir_path = dir_path
        if not kwargs.has_key('session_id'):
            self.save()

    def save(self):
        """Save the session to a file. The algorithm first writes to a temp
        file created in the sessions directory. When all data is written,
        it renames it to the correct name (<session_id>.session)."""
        if not self.dirty:
            return
        session_file = os.path.join(self.dir_path, self.session_id+'.session')
        # write to temp file and then rename
        temp_fd, temp_name = tempfile.mkstemp(dir=self.dir_path)
        temp_file = os.fdopen(temp_fd, 'w+b')
        writer = csv.writer(temp_file)
        writer.writerow([self.session_id,
                         self.serialize(),
                         self.expires,
                         self.ip_address,
                         self.user_agent])
        temp_file.close()
        os.rename(temp_name, session_file)
        self.dirty = False

    @staticmethod
    def load(session_id, directory):
        """Load session from file storage."""
        try:
            session_file_name = os.path.join(directory, session_id+'.session')
            if os.path.isfile(session_file_name):
                session_file = open(session_file_name, 'rb')
                reader = csv.reader(session_file)
                l = reader.next()
                kwargs = DirSession.deserialize(l[1])
                return DirSession(directory, **kwargs)
        except:
            return None

    def delete(self):
        """Deletes the session file."""
        session_file = os.path.join(self.dir_path, self.session_id+'.session')
        if os.path.isfile(session_file):
            os.remove(session_file)


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
        """Store the session data to database. Session is saved only if it
        is necessary. If the table 'tornado_sessions' does not exist yet,
        create it. It uses MySQL's "non-standard insert ... on duplicate key
        "update query."""
        if not self.dirty:
            return
        if not self.connection.get("""show tables like 'tornado_sessions'"""):
            self.connection.execute( # create table if it doesn't exist
                """create table tornado_sessions (
                session_id varchar(64) not null primary key,
                data longtext,
                expires integer,
                ip_address varchar(46),
                user_agent varchar(255)
                );""")

        self.connection.execute( # MySQL's upsert
            """insert into tornado_sessions
            (session_id, data, expires, ip_address, user_agent) values
            (%s, %s, %s, %s, %s)
            on duplicate key update
            session_id=values(session_id), data=values(data), expires=values(expires),
            ip_address=values(ip_address), user_agent=values(user_agent);""",
            self.session_id, self.serialize(), self.expires, self.ip_address,
            self.user_agent)
        self.dirty = False

    @staticmethod
    def load(session_id, connection):
        """Load the stored session."""
        try:
            data = connection.get("""
            select session_id, data, expires, ip_address, user_agent
            from tornado_sessions where session_id = %s;""",  session_id)
            if data:
                kwargs = MySQLSession.deserialize(data['data'])
                return MySQLSession(connection, **kwargs)
            else:
                return None
        except database.ProgrammingError:
            # table does not exist yet, will be created on first save()
            return None

    def delete(self):
        """Remove session data from the database."""
        self.connection.execute("""
        delete from tornado_sessions where session_id = %s;""", self.session_id)


# possible future engines for session storage
class MemcachedSession(BaseSession):
    pass

class MongoDBSession(BaseSession):
    pass
