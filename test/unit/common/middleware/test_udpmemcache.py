# Copyright (c) 2010-2013 OpenStack, LLC.
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

import unittest
import struct
from ConfigParser import NoSectionError
import time

import mock
from eventlet.green.Queue import Queue

from swift.common.middleware.udpmemcache import MemcacheRing, md5hash, \
    STATUS_NO_ERROR, JSON_FLAG, OP_SET, OP_INCREMENT, OP_DECREMENT, \
    OP_DELETE, MemcacheMiddleware, filter_factory, OP_GET, ResponseTimeout, \
    MAX_OFFSET_TIME, sanitize_timeout


UDP_FRAME = '!HHHH'
MEMCACHE_HEADER = '!BBHBBHIIQ'
REQUEST_FRAME = '!HHHHBBHBBHIIQ'  # more or less UDP_FRAME + MEMCACHE_HEADER
REQUEST_FRAME_LEN = struct.calcsize(REQUEST_FRAME)
UDP_FRAME_LEN = struct.calcsize(UDP_FRAME)


class Dummy(object):
    pass


class MockSocket(object):
    AF_INET = 1
    SOCK_DGRAM = 2

    @classmethod
    def socket(cls, family, socktype):
        return MockSocket()

    def close(self):
        pass

    def bind(self, addr):
        return None

    def sendto(self, data, addr):
        self.sent_data = data
        self.sent_addr = addr

    def recvfrom(self, len):
        return '', ('127.0.0.1', 11211)


class MockRing(object):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class MockConfigParser(object):
    def read(self, path):
        self.read_path = path
        return True

    def get(self, section, option):
        if (section, option) == ('memcache', 'memcache_servers'):
            return '127.1.1.1'
        if (section, option) == ('memcache', 'memcache_response_timeout'):
            return '5.0'
        if (section, option) == ('memcache', 'memcache_bind_port'):
            return '111'
        if (section, option) == ('memcache', 'memcache_bind_ip'):
            return '1.1.1.1'


class MockEmptyConfigParser(object):
    def read(self, path):
        return True

    def get(self, section, option):
        raise NoSectionError('whatever')


class TestMemcacheRing(unittest.TestCase):
    def setUp(self):
        with mock.patch('swift.common.middleware.udpmemcache.socket',
                        MockSocket):
            self.ring = MemcacheRing(['127.0.0.1'])
            self.mock_socket = self.ring._udp_socket

    def tearDown(self):
        self.ring.kill()

    def test_server_setting(self):
        with mock.patch('swift.common.middleware.udpmemcache.socket',
                        MockSocket):
            with mock.patch('swift.common.middleware.udpmemcache.spawn',
                            lambda *args: None):
                ring = MemcacheRing(['127.0.0.1'])
                self.assertEquals(ring._errors, {('127.0.0.1', 11211): []})
                ring = MemcacheRing(['127.0.0.1:11212'])
                self.assertEquals(ring._errors, {('127.0.0.1', 11212): []})
                ring = MemcacheRing(['127.0.0.1:11212', '127.0.0.2:12345'])
                self.assertEquals(ring._errors, {('127.0.0.1', 11212): [],
                                                 ('127.0.0.2', 12345): []})

    def test_recv_response(self):
        req_q = Dummy()
        req_q.get = lambda: (1, 1, 'some data')
        self.assertEquals(self.ring._recv_response(req_q), 'some data')

    def test_recv_response_fragmented_out_of_order(self):
        data = iter([(2, 2, 'data'), (1, 2, 'some ')])
        req_q = Dummy()
        req_q.get = lambda: next(data)
        self.assertEquals(self.ring._recv_response(req_q), 'some data')

    def test_parse_response(self):
        # data actually captured from memcache
        status, value, extras = self.ring._parse_response(
            '\x81\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x9b\x00\x00\x00\x02"testvalue"')
        self.assertEquals(status, STATUS_NO_ERROR)
        self.assertEquals(value, '"testvalue"')
        flags = struct.unpack('!I', extras)[0]
        self.assertEquals(flags, JSON_FLAG)

    def test_make_packet(self):
        # generate a packet
        req_id, payload = self.ring._make_packet(
            21, 'testkey', 'testvalue', '')
        # parse it
        (req_id2, seq, count, reserved, magic, opcode, key_len, extras_len,
         data_type, status, body_len, opaque, cas) = \
            struct.unpack(REQUEST_FRAME, payload[:REQUEST_FRAME_LEN])
        # test some key values in the data structure
        self.assertEquals(req_id, req_id2)
        self.assertEquals(seq, 0)
        self.assertEquals(count, 1)
        self.assertEquals(reserved, 0)
        self.assertEquals(magic, 0x80)
        self.assertEquals(opcode, 21)
        self.assertEquals(key_len, len('testkey'))
        self.assertEquals(extras_len, 0)
        self.assertEquals(body_len, len('testkey') + len('testvalue'))
        self.assertEquals(status, STATUS_NO_ERROR)

    def test_get(self):
        stat = STATUS_NO_ERROR
        value = 'some value'
        extras = struct.pack('!I', 0)
        self.ring._send_and_recv = lambda op, key: (stat, value, extras)
        self.assertEquals(self.ring.get('somekey'), 'some value')

    def test_get_json(self):
        stat = STATUS_NO_ERROR
        value = '"some value"'
        extras = struct.pack('!I', JSON_FLAG)
        self.ring._send_and_recv = lambda op, key: (stat, value, extras)
        self.assertEquals(self.ring.get('somekey'), 'some value')

    def test_get_fail(self):
        stat = STATUS_NO_ERROR + 1
        value = ''
        extras = struct.pack('!I', 0)
        self.ring._send_and_recv = lambda op, key: (stat, value, extras)
        self.assertEquals(self.ring.get('somekey'), None)

    def test_set_time(self):

        def send_and_recv(op, key, value, extras):
            set_values.extend([op, key, value, extras])
            return STATUS_NO_ERROR, '', ''
        set_values = []
        self.ring._send_and_recv = send_and_recv
        self.ring.set('somekey', 'somevalue', time=MAX_OFFSET_TIME + 1)
        flag, timeout = struct.unpack('!II', set_values[3])
        self.assert_(timeout > MAX_OFFSET_TIME + 1)

        set_values = []
        self.ring.set('somekey', 'somevalue', time=MAX_OFFSET_TIME)
        flag, timeout = struct.unpack('!II', set_values[3])
        self.assertEquals(timeout, MAX_OFFSET_TIME)

    def test_set(self):
        set_values = []

        def send_and_recv(op, key, value, extras):
            set_values.extend([op, key, value, extras])
            return STATUS_NO_ERROR, '', ''
        self.ring._send_and_recv = send_and_recv
        self.ring.set('somekey', 'somevalue', time=100)
        self.assertEquals(set_values[0], OP_SET)
        self.assertEquals(set_values[1], md5hash('somekey'))
        self.assertEquals(set_values[2], '"somevalue"')
        self.assertEquals(set_values[3],
                          struct.pack('!II', JSON_FLAG, 100))

    def test_set_no_serialization(self):
        set_values = []

        def send_and_recv(op, key, value, extras):
            set_values.extend([op, key, value, extras])
            return STATUS_NO_ERROR, '', ''
        self.ring._send_and_recv = send_and_recv
        self.ring.set('somekey', 'somevalue', time=100, serialize=False)
        self.assertEquals(set_values[2], 'somevalue')
        self.assertEquals(set_values[3],
                          struct.pack('!II', 0, 100))

    def test_incr(self):
        set_values = []

        def send_and_recv(op, key, value, extras):
            set_values.extend([op, key, value, extras])
            value = struct.pack('!Q', 1)
            return STATUS_NO_ERROR, value, ''
        self.ring._send_and_recv = send_and_recv
        self.ring.incr('testkey', 1, time=100)
        self.assertEquals(set_values[0], OP_INCREMENT)
        self.assertEquals(set_values[1], md5hash('testkey'))
        self.assertEquals(set_values[2], '')
        self.assertEquals(set_values[3],
                          struct.pack('!QQI', 1, 1, 100))

    def test_decr(self):
        set_values = []

        def send_and_recv(op, key, value, extras):
            set_values.extend([op, key, value, extras])
            value = struct.pack('!Q', 1)
            return STATUS_NO_ERROR, value, ''
        self.ring._send_and_recv = send_and_recv
        self.ring.decr('testkey', 1, time=100)
        self.assertEquals(set_values[0], OP_DECREMENT)
        self.assertEquals(set_values[1], md5hash('testkey'))
        self.assertEquals(set_values[2], '')
        self.assertEquals(set_values[3],
                          struct.pack('!QQI', 1, 0, 100))

    def test_delete(self):
        set_values = []

        def send_and_recv(op, key):
            set_values.extend([op, key])
            return STATUS_NO_ERROR, '', ''
        self.ring._send_and_recv = send_and_recv
        self.ring.delete('testkey')
        self.assertEquals(set_values[0], OP_DELETE)
        self.assertEquals(set_values[1], md5hash('testkey'))

    def test_set_multi(self):
        sent_messages = []

        def send_and_recv_multi(key, messages):
            responses = []
            sent_messages.extend(messages)
            for message in messages:
                responses.append((STATUS_NO_ERROR, '', ''))
            return responses
        self.ring._send_and_recv_multi = send_and_recv_multi
        self.ring.set_multi({'key1': 'val1', 'key2': 'val2'}, 'key1',
                            time=100)
        for message in sent_messages:
            self.assertEquals(message[0], OP_SET)
            self.assert_(message[1] in (md5hash('key1'), md5hash('key2')))
            self.assert_(message[2] in ('"val1"', '"val2"'))
            self.assertEquals(message[3],
                              struct.pack('!II', JSON_FLAG, 100))

    def test_set_multi_no_serialize(self):
        sent_messages = []

        def send_and_recv_multi(key, messages):
            responses = []
            sent_messages.extend(messages)
            for message in messages:
                responses.append((STATUS_NO_ERROR, '', ''))
            return responses
        self.ring._send_and_recv_multi = send_and_recv_multi
        self.ring.set_multi({'key1': 'val1', 'key2': 'val2'}, 'key1',
                            serialize=False, time=100)
        for message in sent_messages:
            self.assertEquals(message[0], OP_SET)
            self.assert_(message[1] in (md5hash('key1'), md5hash('key2')))
            self.assert_(message[2] in ('val1', 'val2'))
            self.assertEquals(message[3], struct.pack('!II', 0, 100))

    def test_get_multi_failures(self):

        def send_and_recv_multi(key, messages):
            responses = []
            for message in messages:
                responses.append(
                    (STATUS_NO_ERROR + 1, 'val', struct.pack('!I', 0)))
            return responses
        self.ring._send_and_recv_multi = send_and_recv_multi
        resp = self.ring.get_multi(['a', 'b'], 'a')
        self.assertEquals(resp, [None, None])

    def test_get_multi(self):
        sent_messages = []

        def send_and_recv_multi(key, messages):
            responses = []
            sent_messages.extend(messages)
            for message in messages:
                responses.append(
                    (STATUS_NO_ERROR, 'val', struct.pack('!I', 0)))
            return responses
        self.ring._send_and_recv_multi = send_and_recv_multi
        results = self.ring.get_multi(['a', 'b'], 'a')
        self.assertEquals(results, ['val', 'val'])
        for message in sent_messages:
            self.assertEquals(message[0], OP_GET)
            self.assert_(message[1] in (md5hash('a'), md5hash('b')))
            self.assertEquals(message[2], '')

    def test_get_multi_serialized(self):
        sent_messages = []

        def send_and_recv_multi(key, messages):
            responses = []
            sent_messages.extend(messages)
            for message in messages:
                responses.append(
                    (STATUS_NO_ERROR, '"val"', struct.pack('!I', JSON_FLAG)))
            return responses
        self.ring._send_and_recv_multi = send_and_recv_multi
        results = self.ring.get_multi(['a', 'b'], 'a')
        self.assertEquals(results, ['val', 'val'])
        for message in sent_messages:
            self.assertEquals(message[0], OP_GET)
            self.assert_(message[1] in (md5hash('a'), md5hash('b')))

    def test_exception_occurred(self):
        exception_logged = [0]
        addr = ('127.0.0.1', 11211)

        def exception_log(msg, args):
            exception_logged[0] += 1
        with mock.patch('logging.exception', exception_log):
            for x in xrange(15):
                self.ring._exception_occurred(addr, Exception())
        self.assertEquals(exception_logged[0], 15)
        self.assertEquals(len(self.ring._errors[addr]), 15)
        self.assert_(addr in self.ring._error_limited)

    def test_exception_occurred_timeout(self):
        error_logged = [0]
        addr = ('127.0.0.1', 11211)

        def error_log(msg, args):
            error_logged[0] += 1
        with mock.patch('logging.error', error_log):
            for x in xrange(15):
                self.ring._exception_occurred(addr, ResponseTimeout())
        self.assertEquals(error_logged[0], 20)
        self.assertEquals(len(self.ring._errors[addr]), 15)
        self.assert_(addr in self.ring._error_limited)

    def test_send_and_receive(self):
        def recv_response(req_ev):
            return struct.pack(MEMCACHE_HEADER, 0x80, 123, len('testkey'),
                               0, 0, 0, len('testkey') + len('testvalue'),
                               0, 0) + 'testvalue'
        self.ring._recv_response = recv_response
        status, value, extras = self.ring._send_and_recv(
            ('127.0.0.1', 11211), OP_GET, 'testkey')

    def test_send_and_receive_multi(self):
        def recv_response(req_ev):
            data = struct.pack(MEMCACHE_HEADER, 0x80, 123, len('testkey'),
                               0, 0, 0, len('testkey') + len('testvalue'),
                               0, 0) + 'testkey' + 'testvalue'
            return data
        self.ring._recv_response = recv_response
        messages = [
            (OP_GET, 'testkey1', '', ''),
            (OP_GET, 'testkey2', '', ''),
            (OP_GET, 'testkey3', '', '')]
        responses = self.ring._send_and_recv_multi(
            ('127.0.0.1', 11211), messages)
        self.assertEquals(
            responses, [(STATUS_NO_ERROR, 'testvalue', ''),
                        (STATUS_NO_ERROR, 'testvalue', ''),
                        (STATUS_NO_ERROR, 'testvalue', '')])

    def test_udp_runner(self):
        req_id = 12345
        queue = Queue()
        self.ring._udp_dispatch[req_id] = queue

        def recvfrom(length):
            self.ring._udp_running = False
            return (struct.pack(UDP_FRAME, req_id, 0, 1, 0),
                    ('127.0.0.1', 11211))
        self.mock_socket.recvfrom = recvfrom
        self.ring._udp_runner()
        seq, count, payload = queue.get()
        self.assertEquals(seq, 0)
        self.assertEquals(count, 1)
        self.assertEquals(payload, '')

    def test_get_servers(self):
        with mock.patch('swift.common.middleware.udpmemcache.socket',
                        MockSocket):
            with mock.patch('swift.common.middleware.udpmemcache.spawn',
                            lambda *args: None):
                ring = MemcacheRing(['127.0.0.1:11212', '127.0.0.1:11213',
                                     '127.0.0.1:11214', '127.0.0.1:11215'])
                servers = [x for x in ring._get_servers('somekey')]
                self.assert_(('127.0.0.1', 11212) in servers)
                for x in xrange(15):
                    ring._exception_occurred(('127.0.0.1', 11212),
                                             Exception())
                servers = [x for x in ring._get_servers('somekey')]
                self.assert_(('127.0.0.1', 11212) not in servers)

    def test_sanitize_timeout(self):
        now = time.time()
        self.assertEquals(sanitize_timeout(100), 100)
        self.assert_(sanitize_timeout(MAX_OFFSET_TIME + 1) > now)


class TestMiddlewareConfig(unittest.TestCase):
    def test_filter_factory(self):
        with mock.patch(
                'swift.common.middleware.udpmemcache.MemcacheRing', MockRing):
            fact = filter_factory({})
            self.assert_(callable(fact))
            mid = fact(None)
            self.assert_(isinstance(mid, MemcacheMiddleware))

    def test_no_config(self):
        with mock.patch(
                'swift.common.middleware.udpmemcache.MemcacheRing', MockRing):
            mid = MemcacheMiddleware(None, {})
        self.assertEquals(mid.memcache.args, (['127.0.0.1'],))
        self.assertEquals(mid.memcache.kwargs,
                          {'bind_port': 0, 'response_timeout': 1.0,
                           'bind_ip': '0.0.0.0'})

    def test_some_config(self):
        with mock.patch(
                'swift.common.middleware.udpmemcache.MemcacheRing', MockRing):
            mid = MemcacheMiddleware(
                None, {'memcache_servers': '192.168.1.1',
                       'memcache_bind_port': '123',
                       'memcache_bind_ip': '127.0.0.1',
                       'memcache_response_timeout': '2.0'})
        self.assertEquals(mid.memcache.args, (['192.168.1.1'],))
        self.assertEquals(mid.memcache.kwargs,
                          {'bind_port': 123, 'response_timeout': 2.0,
                           'bind_ip': '127.0.0.1'})

    def test_weirdo_config(self):
        with mock.patch(
                'swift.common.middleware.udpmemcache.MemcacheRing', MockRing):
            with mock.patch(
                    'swift.common.middleware.udpmemcache.ConfigParser',
                    MockConfigParser):
                mid = MemcacheMiddleware(None, {})
        self.assertEquals(mid.memcache.args, (['127.1.1.1'],))
        self.assertEquals(
            mid.memcache.kwargs,
            {'bind_port': 111, 'response_timeout': 5.0, 'bind_ip': '1.1.1.1'})

    def test_default_config(self):
        with mock.patch(
                'swift.common.middleware.udpmemcache.MemcacheRing', MockRing):
            with mock.patch(
                    'swift.common.middleware.udpmemcache.ConfigParser',
                    MockEmptyConfigParser):
                mid = MemcacheMiddleware(None, {})
        self.assertEquals(mid.memcache.args, (['127.0.0.1'],))

    def test_call(self):
        with mock.patch(
                'swift.common.middleware.udpmemcache.MemcacheRing', MockRing):
            def mock_app(env, start_response):
                return ['hi']
            mid = MemcacheMiddleware(mock_app, {})
            env = {}
            start_response = lambda *args: None
            result = mid(env, start_response)
            self.assertEquals(result, ['hi'])
