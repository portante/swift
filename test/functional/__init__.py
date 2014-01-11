# Copyright (c) 2014 OpenStack Foundation
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

import os
import time
import pickle
from contextlib import closing
from gzip import GzipFile
from shutil import rmtree
from tempfile import mkdtemp

import eventlet
from eventlet import spawn, wsgi, listen

from test.unit import debug_logger, FakeMemcache
from swift.common import utils
from swift.common import ring
from swift.common.wsgi import monkey_patch_mimetools
from swift.proxy import server as proxy_server
from swift.account import server as account_server
from swift.container import server as container_server
from swift.obj import server as object_server
import swift.proxy.controllers.obj

from swift.common.middleware import catch_errors, gatekeeper, healthcheck, \
    proxy_logging, bulk, tempurl, slo, dlo, ratelimit, tempauth, \
    container_quotas, account_quotas

STATIC_TIME = time.time()
_testdir = _test_servers = _test_sockets = _test_coros = None


class FakeMemcacheMiddleware(object):
    """
    Caching middleware that fakes out caching in swift.
    """

    def __init__(self, app, conf):
        self.app = app
        self.memcache = FakeMemcache()

    def __call__(self, env, start_response):
        env['swift.cache'] = self.memcache
        return self.app(env, start_response)


in_process_conf = {}


def in_process_setup(the_object_server=object_server):
    utils.HASH_PATH_SUFFIX = 'endcap'
    global _testdir, _test_servers, _test_sockets, _test_coros
    monkey_patch_mimetools()
    _testdir = \
        os.path.join(mkdtemp(), 'tmp_functional')
    utils.mkdirs(_testdir)
    rmtree(_testdir)
    utils.mkdirs(os.path.join(_testdir, 'sda1'))
    utils.mkdirs(os.path.join(_testdir, 'sda1', 'tmp'))
    utils.mkdirs(os.path.join(_testdir, 'sdb1'))
    utils.mkdirs(os.path.join(_testdir, 'sdb1', 'tmp'))
    prolis = listen(('localhost', 0))
    conf = {'devices': _testdir, 'swift_dir': _testdir, 'mount_check': 'false',
            'max_file_size': str(10 * 1024 * 1024),
            'allow_account_management': 'true',
            'account_autocreate': 'true',
            'allowed_headers':
            'content-disposition, content-encoding, x-delete-at,'
            ' x-object-manifest, x-static-large-object',
            'allow_versions': 'True',
            'auth_host': '127.0.0.1',
            'auth_port': str(prolis.getsockname()[1]),
            'auth_ssl': 'no',
            'auth_prefix': '/auth/',
            # Primary functional test account (needs admin access to the
            # account)
            'account': 'test',
            'username': 'tester',
            'password': 'testing',
            # User on a second account (needs admin access to the account)
            'account2': 'test2',
            'username2': 'tester2',
            'password2': 'testing2',
            # User on same account as first, but without admin access
            'username3': 'tester3',
            'password3': 'testing3',
            # For tempauth middleware
            'user_admin_admin': 'admin .admin .reseller_admin',
            'user_test_tester': 'testing .admin',
            'user_test2_tester2': 'testing2 .admin',
            'user_test_tester3': 'testing3'}

    acc1lis = listen(('localhost', 0))
    acc2lis = listen(('localhost', 0))
    con1lis = listen(('localhost', 0))
    con2lis = listen(('localhost', 0))
    obj1lis = listen(('localhost', 0))
    obj2lis = listen(('localhost', 0))
    _test_sockets = \
        (prolis, acc1lis, acc2lis, con1lis, con2lis, obj1lis, obj2lis)
    account_ring_path = os.path.join(_testdir, 'account.ring.gz')
    with closing(GzipFile(account_ring_path, 'wb')) as f:
        pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                    [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                      'port': acc1lis.getsockname()[1]},
                     {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                      'port': acc2lis.getsockname()[1]}], 30),
                    f)
    container_ring_path = os.path.join(_testdir, 'container.ring.gz')
    with closing(GzipFile(container_ring_path, 'wb')) as f:
        pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                    [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                      'port': con1lis.getsockname()[1]},
                     {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                      'port': con2lis.getsockname()[1]}], 30),
                    f)
    object_ring_path = os.path.join(_testdir, 'object.ring.gz')
    with closing(GzipFile(object_ring_path, 'wb')) as f:
        pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                    [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                      'port': obj1lis.getsockname()[1]},
                     {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                      'port': obj2lis.getsockname()[1]}], 30),
                    f)

    wsgi.HttpProtocol.default_request_version = "HTTP/1.0"
    # Turn off logging requests by the underlying WSGI software.
    wsgi.HttpProtocol.log_request = lambda *a: None
    logger = utils.get_logger(conf, 'wsgi-server', log_route='wsgi')
    # Redirect logging other messages by the underlying WSGI software.
    wsgi.HttpProtocol.log_message = \
        lambda s, f, *a: logger.error('ERROR WSGI: ' + f % a)
    wsgi.WRITE_TIMEOUT = int(conf.get('client_timeout') or 60)

    eventlet.hubs.use_hub(utils.get_hub())
    eventlet.patcher.monkey_patch(all=False, socket=True)
    eventlet.debug.hub_exceptions(True)

    prosrv = proxy_server.Application(conf, logger=debug_logger('proxy'))
    acc1srv = account_server.AccountController(
        conf, logger=debug_logger('acct1'))
    acc2srv = account_server.AccountController(
        conf, logger=debug_logger('acct2'))
    con1srv = container_server.ContainerController(
        conf, logger=debug_logger('cont1'))
    con2srv = container_server.ContainerController(
        conf, logger=debug_logger('cont2'))
    obj1srv = the_object_server.ObjectController(
        conf, logger=debug_logger('obj1'))
    obj2srv = the_object_server.ObjectController(
        conf, logger=debug_logger('obj2'))
    _test_servers = \
        (prosrv, acc1srv, acc2srv, con1srv, con2srv, obj1srv, obj2srv)

    pl0_prosv = proxy_logging.ProxyLoggingMiddleware(
        prosrv, conf, logger=prosrv.logger)
    aq_prosrv = account_quotas.AccountQuotaMiddleware(
        pl0_prosv, conf, logger=prosrv.logger)
    utils.register_swift_info('account_quotas')
    ct_prosrv = container_quotas.ContainerQuotaMiddleware(
        aq_prosrv, conf)
    utils.register_swift_info('container_quotas')
    ta_prosrv = tempauth.TempAuth(
        ct_prosrv, conf)
    rl_prosrv = ratelimit.RateLimitMiddleware(
        ta_prosrv, conf, logger=prosrv.logger)
    utils.register_swift_info('ratelimit')
    dl_prosrv = dlo.DynamicLargeObject(
        rl_prosrv, conf)
    sl_prosrv = slo.StaticLargeObject(
        dl_prosrv, conf)
    utils.register_swift_info('slo')
    tu_prosrv = tempurl.TempURL(
        sl_prosrv, conf)
    utils.register_swift_info('tempurl', methods='GET HEAD PUT'.split())
    bk_prosrv = bulk.Bulk(
        tu_prosrv, conf)
    # FIXME: need an in-memory memcache middleware here
    mc_prosrv = FakeMemcacheMiddleware(
        bk_prosrv, conf)
    pl1_prosrv = proxy_logging.ProxyLoggingMiddleware(
        mc_prosrv, conf, logger=prosrv.logger)
    hc_prosrv = healthcheck.HealthCheckMiddleware(
        pl1_prosrv, conf)
    gk_prosrv = gatekeeper.GatekeeperMiddleware(
        hc_prosrv, conf)
    ce_prosrv = catch_errors.CatchErrorMiddleware(
        gk_prosrv, conf)

    nl = utils.NullLogger()
    prospa = spawn(wsgi.server, prolis, ce_prosrv, nl)
    acc1spa = spawn(wsgi.server, acc1lis, acc1srv, nl)
    acc2spa = spawn(wsgi.server, acc2lis, acc2srv, nl)
    con1spa = spawn(wsgi.server, con1lis, con1srv, nl)
    con2spa = spawn(wsgi.server, con2lis, con2srv, nl)
    obj1spa = spawn(wsgi.server, obj1lis, obj1srv, nl)
    obj2spa = spawn(wsgi.server, obj2lis, obj2srv, nl)
    _test_coros = \
        (prospa, acc1spa, acc2spa, con1spa, con2spa, obj1spa, obj2spa)

    # Create accounts "test" and "test2"
    def create_account(act):
        ts = utils.normalize_timestamp(time.time())
        partition, nodes = prosrv.account_ring.get_nodes(act)
        for node in nodes:
            # Note: we are just using the http_connect method in the object
            # controller here to talk to the account server nodes.
            conn = swift.proxy.controllers.obj.http_connect(
                node['ip'], node['port'], node['device'], partition, 'PUT',
                '/' + act, {'X-Timestamp': ts, 'x-trans-id': act})
            resp = conn.getresponse()
            assert(resp.status == 201)

    create_account('AUTH_test')
    create_account('AUTH_test2')
    global in_process_conf
    in_process_conf = conf


in_process = False


def setup_package():
    global in_process
    if in_process:
        in_process_setup()


def in_process_teardown():
    for server in _test_coros:
        server.kill()
    rmtree(os.path.dirname(_testdir))


def teardown_package():
    global in_process
    if in_process:
        in_process_teardown()
