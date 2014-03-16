# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from httplib import HTTPException
import os
import socket
import sys
from time import sleep
from urlparse import urlparse

from test import get_config

from swiftclient import get_auth, http_connection

conf = get_config('func_test')
web_front_end = conf.get('web_front_end', 'integral')
normalized_urls = conf.get('normalized_urls', False)

# If no conf was read, we will fall back to old school env vars
swift_test_auth_version = '1'
swift_test_auth = os.environ.get('SWIFT_TEST_AUTH')
swift_test_user = [os.environ.get('SWIFT_TEST_USER'), None, None]
swift_test_key = [os.environ.get('SWIFT_TEST_KEY'), None, None]
swift_test_tenant = ['', '', '']
swift_test_perm = ['', '', '']


def do_setup(conf):
    global swift_test_auth_version
    global swift_test_auth
    global swift_test_user
    global swift_test_key
    global swift_test_tenant
    global swift_test_perm

    swift_test_auth_version = str(conf.get('auth_version', '1'))

    swift_test_auth = 'http'
    if conf.get('auth_ssl', 'no').lower() in ('yes', 'true', 'on', '1'):
        swift_test_auth = 'https'
    if 'auth_prefix' not in conf:
        conf['auth_prefix'] = '/'
    try:
        suffix = '://%(auth_host)s:%(auth_port)s%(auth_prefix)s' % conf
        swift_test_auth += suffix
    except KeyError:
        pass  # skip

    if swift_test_auth_version == "1":
        swift_test_auth += 'v1.0'

        if 'account' in conf:
            swift_test_user[0] = '%(account)s:%(username)s' % conf
        else:
            swift_test_user[0] = '%(username)s' % conf
        swift_test_key[0] = conf['password']
        try:
            swift_test_user[1] = '%s%s' % (
                '%s:' % conf['account2'] if 'account2' in conf else '',
                conf['username2'])
            swift_test_key[1] = conf['password2']
        except KeyError:
            pass  # old conf, no second account tests can be run
        try:
            swift_test_user[2] = '%s%s' % ('%s:' % conf['account'] if 'account'
                                           in conf else '', conf['username3'])
            swift_test_key[2] = conf['password3']
        except KeyError:
            pass  # old conf, no third account tests can be run

        for _ in range(3):
            swift_test_perm[_] = swift_test_user[_]

    else:
        swift_test_user[0] = conf['username']
        swift_test_tenant[0] = conf['account']
        swift_test_key[0] = conf['password']
        swift_test_user[1] = conf['username2']
        swift_test_tenant[1] = conf['account2']
        swift_test_key[1] = conf['password2']
        swift_test_user[2] = conf['username3']
        swift_test_tenant[2] = conf['account']
        swift_test_key[2] = conf['password3']

        for _ in range(3):
            swift_test_perm[_] = swift_test_tenant[_] + ':' \
                + swift_test_user[_]


if conf:
    do_setup(conf)

use_in_process = False
skip = not all([swift_test_auth, swift_test_user[0], swift_test_key[0]])
if skip:
    if conf:
        print >>sys.stderr, 'SKIPPING FUNCTIONAL TESTS DUE TO NO CONFIG'
    else:
        # setup defaults for in-process
        use_in_process = True

skip2 = not all([not skip, swift_test_user[1], swift_test_key[1]])
if not skip and skip2:
    if conf:
        print >>sys.stderr, (
            'SKIPPING SECOND ACCOUNT FUNCTIONAL TESTS'
            ' DUE TO NO CONFIG FOR THEM')
    else:
        # setup defaults for in-process
        use_in_process = True

skip3 = not all([not skip, swift_test_user[2], swift_test_key[2]])
if not skip and skip3:
    if conf:
        print >>sys.stderr, (
            'SKIPPING THIRD ACCOUNT FUNCTIONAL TESTS'
            ' DUE TO NO CONFIG FOR THEM')
    else:
        # setup defaults for in-process
        use_in_process = True


if use_in_process:
    # If we decided to use the in-process functional test configuration, since
    # we were skippings tests due to a lack of any configuration file, then
    # don't skip anything, do_setup() will be called again above with a
    # in-process config dictionary.
    skip = skip2 = skip3 = False


class AuthError(Exception):
    pass


class InternalServerError(Exception):
    pass


url = [None, None, None]
token = [None, None, None]
parsed = [None, None, None]
conn = [None, None, None]


def retry(func, *args, **kwargs):
    """
    You can use the kwargs to override:
      'retries' (default: 5)
      'use_account' (default: 1) - which user's token to pass
      'url_account' (default: matches 'use_account') - which user's storage URL
      'resource' (default: url[url_account] - URL to connect to; retry()
          will interpolate the variable :storage_url: if present
    """
    global url, token, parsed, conn
    retries = kwargs.get('retries', 5)
    attempts, backoff = 0, 1

    # use account #1 by default; turn user's 1-indexed account into 0-indexed
    use_account = kwargs.pop('use_account', 1) - 1

    # access our own account by default
    url_account = kwargs.pop('url_account', use_account + 1) - 1

    while attempts <= retries:
        attempts += 1
        try:
            if not url[use_account] or not token[use_account]:
                url[use_account], token[use_account] = \
                    get_auth(swift_test_auth, swift_test_user[use_account],
                             swift_test_key[use_account],
                             snet=False,
                             tenant_name=swift_test_tenant[use_account],
                             auth_version=swift_test_auth_version,
                             os_options={})
                parsed[use_account] = conn[use_account] = None
            if not parsed[use_account] or not conn[use_account]:
                parsed[use_account], conn[use_account] = \
                    http_connection(url[use_account])

            # default resource is the account url[url_account]
            resource = kwargs.pop('resource', '%(storage_url)s')
            template_vars = {'storage_url': url[url_account]}
            parsed_result = urlparse(resource % template_vars)
            return func(url[url_account], token[use_account],
                        parsed_result, conn[url_account],
                        *args, **kwargs)
        except (socket.error, HTTPException):
            if attempts > retries:
                raise
            parsed[use_account] = conn[use_account] = None
        except AuthError:
            url[use_account] = token[use_account] = None
            continue
        except InternalServerError:
            pass
        if attempts <= retries:
            sleep(backoff)
            backoff *= 2
    raise Exception('No result after %s retries.' % retries)


def check_response(conn):
    resp = conn.getresponse()
    if resp.status == 401:
        resp.read()
        raise AuthError()
    elif resp.status // 100 == 5:
        resp.read()
        raise InternalServerError()
    return resp
