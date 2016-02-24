# -*- coding: utf-8 -*-

import hmac
import sys
from base64 import urlsafe_b64encode
from hashlib import sha1
from requests.auth import AuthBase
from httpie.plugins.base import AuthPlugin

# -------
# Pythons
# -------

_ver = sys.version_info

#: Python 2.x?
is_py2 = (_ver[0] == 2)

#: Python 3.x?
is_py3 = (_ver[0] == 3)


# ---------
# Specifics
# ---------

if is_py2:
    from urlparse import urlparse  # noqa
    import StringIO
    StringIO = BytesIO = StringIO.StringIO

    builtin_str = str
    bytes = str
    str = unicode  # noqa
    basestring = basestring  # noqa
    numeric_types = (int, long, float)  # noqa

    def b(data):
        return bytes(data)

    def s(data):
        return bytes(data)

    def u(data):
        return unicode(data, 'unicode_escape')  # noqa

elif is_py3:
    from urllib.parse import urlparse  # noqa
    import io
    StringIO = io.StringIO
    BytesIO = io.BytesIO

    builtin_str = str
    str = str
    bytes = bytes
    basestring = (str, bytes)
    numeric_types = (int, float)

    def b(data):
        if isinstance(data, str):
            return data.encode('utf-8')
        return data

    def s(data):
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return data

    def u(data):
        return data

def urlsafe_base64_encode(data):
    """
    http://developer.qiniu.com/docs/v6/api/overview/appendix.html#urlsafe-base64
    """

    ret = urlsafe_b64encode(b(data))
    return s(ret)

class QiniuMacAuthSign(object):
    """
    Sign Requests

    Attributes:
        __access_key
        __secret_key
    """

    def __init__(self, access_key, secret_key):
        self.__checkKey(access_key, secret_key)
        self.__access_key = access_key
        self.__secret_key = b(secret_key)

    def __token(self, data):
        data = b(data)
        hashed = hmac.new(self.__secret_key, data, sha1)
        return urlsafe_base64_encode(hashed.digest())

    def token_of_request(self, method, host, url, content_type=None, body=None):
        """
        <Method> <PathWithRawQuery>
        Host: <Host>
        Content-Type: <ContentType>

        [<Body>] #这里的 <Body> 只有在 <ContentType> 存在且不为 application/octet-stream 时才签进去。

        """
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query

        if not host:
            host = netloc

        path_with_query = path
        if query != '':
            path_with_query = ''.join([path_with_query, '?', query])
        data = ''.join(["%s %s"%(method, path_with_query) , "\n", "Host: %s"%host, "\n"])

        if content_type:
            data += "Content-Type: %s"%s(content_type) + "\n\n"
            if content_type != "application/octet-stream" and body:
                data += body
        else:
            data += "\n"

        return '{0}:{1}'.format(self.__access_key, self.__token(data))

    @staticmethod
    def __checkKey(access_key, secret_key):
        if not (access_key and secret_key):
            raise ValueError('QiniuMacAuthSign : Invalid key')

class QiniuMacAuth(AuthBase):
    def __init__(self, auth):
        self.auth = auth

    def __call__(self, r):
        token = self.auth.token_of_request(
            r.method, r.headers.get('Host', None),
            r.url, r.headers.get('Content-Type', None),
            r.body
            )
        r.headers['Authorization'] = 'Qiniu {0}'.format(token)
        return r

class QiniuMacAuthPlugin(AuthPlugin):

    name = 'Qiniu Mac HTTP auth'
    auth_type = 'qiniu/mac'
    package_name = 'qiniu.com'

    def get_auth(self, ak, sk):
        return QiniuMacAuth(QiniuMacAuthSign(ak, sk))
