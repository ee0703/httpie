# -*- coding: utf-8 -*-

import hmac
import sys
from base64 import urlsafe_b64encode
from hashlib import sha1
from datetime import datetime
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

class QboxMacAuthSign(object):
    """
    Sign Requests

    Attributes:
        __access_key
        __secret_key

    http://developer.qiniu.com/article/developer/security/access-token.html
    https://github.com/qiniu/python-sdk/blob/master/qiniu/auth.py
    """

    def __init__(self, access_key, secret_key):
        self.__checkKey(access_key, secret_key)
        self.__access_key = access_key
        self.__secret_key = b(secret_key)

    def __token(self, data):
        data = b(data)
        hashed = hmac.new(self.__secret_key, data, sha1)
        return urlsafe_base64_encode(hashed.digest())

    def token_of_request(self, url, body=None, content_type=None):
        """带请求体的签名（本质上是管理凭证的签名）
        Args:
            url:          待签名请求的url
            body:         待签名请求的body
            content_type: 待签名请求的body的Content-Type
        Returns:
            管理凭证
        """
        parsed_url = urlparse(url)
        query = parsed_url.query
        path = parsed_url.path
        data = path
        if query != '':
            data = ''.join([data, '?', query])
        data = ''.join([data, "\n"])

        if body:
            mimes = [
                'application/x-www-form-urlencoded'
            ]
            if content_type in mimes:
                data += body

        return '{0}:{1}'.format(self.__access_key, self.__token(data))


    @staticmethod
    def __checkKey(access_key, secret_key):
        if not (access_key and secret_key):
            raise ValueError('QboxMacAuthSign : Invalid key')

class QboxMacAuth(AuthBase):
    def __init__(self, auth):
        self.auth = auth

    def __call__(self, r):
        token = None
        if r.body is not None and r.headers['Content-Type'] == 'application/x-www-form-urlencoded':
            token = self.auth.token_of_request(r.url, r.body, 'application/x-www-form-urlencoded')
        else:
            token = self.auth.token_of_request(r.url)
        r.headers['Authorization'] = 'QBox {0}'.format(token)
        return r

class QboxMacAuthPlugin(AuthPlugin):

    name = 'Qbox Mac HTTP auth'
    auth_type = 'qbox/mac'
    package_name = 'qiniu.com'

    def get_auth(self, ak, sk):
        return QboxMacAuth(QboxMacAuthSign(ak, sk))

class QiniuMacAuthSign(object):
    """
    Sign Requests

    Attributes:
        __access_key
        __secret_key

    http://kirk-docs.qiniu.com/apidocs/#TOC_325b437b89e8465e62e958cccc25c63f
    """

    def __init__(self, access_key, secret_key):
        self.qiniu_header_prefix = "X-Qiniu-"
        self.__checkKey(access_key, secret_key)
        self.__access_key = access_key
        self.__secret_key = b(secret_key)

    def __token(self, data):
        data = b(data)
        hashed = hmac.new(self.__secret_key, data, sha1)
        return urlsafe_base64_encode(hashed.digest())

    def token_of_request(self, method, host, url, qheaders, content_type=None, body=None):
        """
        <Method> <PathWithRawQuery>
        Host: <Host>
        Content-Type: <ContentType>
        [<X-Qiniu-*> Headers]

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
            data += "Content-Type: %s"%s(content_type) + "\n"

        data += qheaders
        data += "\n"

        if content_type and content_type != "application/octet-stream" and body:
            data += body

        return '{0}:{1}'.format(self.__access_key, self.__token(data))

    def qiniu_headers(self, headers):
        res = ""
        for key in headers:
            if key.startswith(self.qiniu_header_prefix):
                res += key+": %s\n"%s(headers.get(key))
        return res

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
            r.url, self.auth.qiniu_headers(r.headers),
            r.headers.get('Content-Type', None),
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

class PandoraMacSign(object):
    """
    Sign Requests

    Attributes:
        __access_key
        __secret_key

    Diff to qiniu/mac:

    1. Do not Sign <Body>
    2. Do not Sign Header["Host"]
    3. Alway add Header["Date"]: golang.http.TimeFormat and Sign Header["Date"]

        http.TimeFormat is the time format to use when generating times in HTTP headers.
        It is like time.RFC1123 but hard-codes GMT as the time zone.
        The time being formatted must be in UTC for Format to generate the correct format.

    4. Sign Header["Content-MD5"] if exists (Optional)
    4. Sign Header["X-Qiniu-*"] if exists (Optional)

    """

    def __init__(self, access_key, secret_key):
        self.qiniu_header_prefix = "X-Qiniu-"
        self.__checkKey(access_key, secret_key)
        self.__access_key = access_key
        self.__secret_key = b(secret_key)

    def __token(self, data):
        data = b(data)
        hashed = hmac.new(self.__secret_key, data, sha1)
        return urlsafe_base64_encode(hashed.digest())

    def token_of_request(self, method, cmd5, ctype, date, url, qheaders):
        """
        <Method>
        Header["Content-MD5"]
        Header["Content-Type"]
        Header["Date"]

        Header["X-Qiniu-1"]
        Header["X-Qiniu-1"]<PathWithSomeQuery>
        """

        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        path_with_query = path

        if query != '':
            path_with_query = ''.join([path_with_query, '?', query])

        data = method
        data += "\n%s"%s(cmd5)
        data += "\n%s"%s(ctype)
        data += "\n%s\n"%s(date)
        data += qheaders
        # TODO only path now
        data += path

        return '{0}:{1}'.format(self.__access_key, self.__token(data))

    def qiniu_headers(self, headers):
        res = ""
        for key in headers:
            if key.startswith(self.qiniu_header_prefix):
                res += "\n" + key.lower()+":%s"%s(headers.get(key))
        return res

    @staticmethod
    def __checkKey(access_key, secret_key):
        if not (access_key and secret_key):
            raise ValueError('PandoraMacSign : Invalid key')

class PandoraMacAuth(AuthBase):
    def __init__(self, auth):
        self.auth = auth
        self.date_format = "%a, %d %b %Y %H:%M:%S GMT"

    def __call__(self, r):
        now = datetime.utcnow().strftime(self.date_format)
        token = self.auth.token_of_request(
            r.method,
            r.headers.get('Content-MD5', ""),
            r.headers.get('Content-Type', ""),
            now,
            r.url,
            self.auth.qiniu_headers(r.headers)
            )
        r.headers['Authorization'] = 'Pandora {0}'.format(token)
        r.headers['Date'] = now
        return r

class PandoraMacAuthPlugin(AuthPlugin):

    name = 'Pandora Mac HTTP auth'
    auth_type = 'pandora/mac'
    package_name = 'qiniu.com'

    def get_auth(self, ak, sk):
        return PandoraMacAuth(PandoraMacSign(ak, sk))
