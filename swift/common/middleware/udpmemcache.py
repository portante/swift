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

"""
A consistent-hashed memcache client that communicates using UDP.
Intended to be a drop-in replacement for the normal swift cache middleware.

It doesn't support pickling or unpickling values.  If you want to use this and
you were on pickles, you'll probably have to go through the pickle->json
upgrade progression with the regular middleware first.

It uses the same hashing scheme, so keys shouldn't get moved around when you
switch between them.

It also uses the same basic error limiting methodology from the normal swift
cache middleware, for better or worse.
"""

import struct
import logging
import time
from bisect import bisect
import os
from ConfigParser import ConfigParser, NoSectionError, NoOptionError
from gettext import gettext as _

from eventlet import spawn, Timeout
from eventlet.green import socket
from eventlet.green.Queue import Queue

# compat, callers sometimes expect us to raise this exact error
from swift.common.memcached import MemcacheConnectionError, \
    sanitize_timeout, md5hash
from swift.common.utils import json


DEFAULT_MEMCACHE_PORT = 11211

RESPONSE_TIMEOUT = 1.0  # in seconds
JSON_FLAG = 2
NODE_WEIGHT = 50
TRY_COUNT = 3
MAX_OFFSET_TIME = (30 * 24 * 60 * 60)
# protocol has 2 unsigned bytes for request id
MAX_REQUEST_ID = 65535

# if ERROR_LIMIT_COUNT errors occur in ERROR_LIMIT_TIME seconds, the server
# will be considered failed for ERROR_LIMIT_DURATION seconds.
ERROR_LIMIT_COUNT = 10
ERROR_LIMIT_TIME = 60
ERROR_LIMIT_DURATION = 60

# some struct definitions
UDP_FRAME = '!HHHH'
MEMCACHE_HEADER = '!BBHBBHIIQ'
REQUEST_FRAME = '!HHHHBBHBBHIIQ'  # more or less UDP_FRAME + MEMCACHE_HEADER
UDP_FRAME_LEN = struct.calcsize(UDP_FRAME)
MEMCACHE_HEADER_LEN = struct.calcsize(MEMCACHE_HEADER)

STATUS_NO_ERROR = 0x0

OP_GET = 0x00
OP_SET = 0x01
OP_DELETE = 0x04
OP_INCREMENT = 0x05
OP_DECREMENT = 0x06


class ResponseTimeout(Timeout):
    """
    Timeout subclass raised when a request has waited too long for a response.
    Is caught by individual operations and passed to _exception_occurred.
    """
    pass


class MemcacheRing(object):
    """
    A consistent-hashed memcache client that communicates using UDP.
    Intended to be a drop-in replacement for the normal swift memcache
    middleware.
    """
    def __init__(self, servers, response_timeout=RESPONSE_TIMEOUT,
                 tries=TRY_COUNT, bind_ip='0.0.0.0', bind_port=0):
        self._ring = {}
        self._errors = {}
        self._error_limited = {}
        for server in sorted(servers):
            if ':' in server:
                host, port = server.split(':')
                addr = (host, int(port))
            else:
                addr = (server, DEFAULT_MEMCACHE_PORT)
            for i in xrange(NODE_WEIGHT):
                self._ring[md5hash('%s-%s' % (server, i))] = addr
            self._error_limited[addr] = 0
            self._errors[addr] = []
        self._sorted = sorted(self._ring)
        self._response_timeout = response_timeout
        self._tries = tries if tries <= len(servers) else len(servers)

        self._udp_running = True
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.bind((bind_ip, bind_port))
        self._udp_response_id = 0
        self._udp_dispatch = {}
        self._udp_dispatch_thread = spawn(self._udp_runner)

    def _udp_runner(self):
        """
        This method gets spawned in a greenlet when the memcache ring is
        created.  It parse packet frames and dispatches them to any listening
        greenlets with the correct request id.
        """
        while self._udp_running:
            data, addr = self._udp_socket.recvfrom(65536)
            req_id, seq, count, res = struct.unpack(
                UDP_FRAME, data[:UDP_FRAME_LEN])
            if req_id in self._udp_dispatch:
                payload = data[UDP_FRAME_LEN:]
                self._udp_dispatch[req_id].put((seq, count, payload))

    def kill(self):
        """
        Stop the dispatch thread and close the UDP server.
        """
        self._udp_running = False
        self._udp_dispatch_thread.kill()
        self._udp_socket.close()

    def _exception_occurred(self, addr, e):
        """
        Report exception `e` on server `addr`.
        The exception is logged and factored into error limiting for the
        given server.

        :param addr: (ip, port) for the server
        :param e: exception that occurred
        """
        if isinstance(e, ResponseTimeout):
            logging.error(_("Timeout talking to memcached: %s"), addr)
        else:
            logging.exception(_("Error talking to memcached: %s"), addr)
        now = time.time()
        self._errors[addr].append(now)
        if len(self._errors[addr]) > ERROR_LIMIT_COUNT:
            self._errors[addr] = [err for err in self._errors[addr]
                                  if err > now - ERROR_LIMIT_TIME]
            if len(self._errors[addr]) > ERROR_LIMIT_COUNT:
                self._error_limited[addr] = now + ERROR_LIMIT_DURATION
                logging.error(_('Error limiting server %s'), addr)

    def _get_servers(self, key):
        """
        Return an iterator of (ip, port) tuples for the given key, based on
        consisten hashing.  Error-limited nodes are filtered out.

        :param key: key to get a server associated with
        :returns: iterator of (ip, port) tuples
        """
        pos = bisect(self._sorted, key)
        served = []
        while len(served) < self._tries:
            pos = (pos + 1) % len(self._sorted)
            addr = self._ring[self._sorted[pos]]
            if addr in served:
                continue
            served.append(addr)
            if self._error_limited[addr] > time.time():
                continue
            # try each server twice
            yield addr
            yield addr

    def _recv_response(self, req_q):
        """
        Wait for any packets in the response, reassemble them in order, and
        return the completed response.

        :param req_q: Queue on which to wait for packet notification
        :returns: re-assembled response payload
        """
        packets = []
        packet_count = 1
        while len(packets) < packet_count:
            seq, packet_count, payload = req_q.get()
            packets.append((seq, payload))
        packets.sort()  # sorts packets by sequence number
        return ''.join(packet[1] for packet in packets)

    def _parse_response(self, response):
        """
        Parse a memcache protocol response into the status, value and extras
        fields, which are its primary payloads.

        :param response: buffer containing the response data
        :returns: tuple of (status, value, extras)
        """
        (magic, opcode, key_len, extras_len, data_type, status, body_len,
         opaque, cas) = struct.unpack(MEMCACHE_HEADER,
                                      response[:MEMCACHE_HEADER_LEN])
        extras = response[MEMCACHE_HEADER_LEN + key_len:
                          MEMCACHE_HEADER_LEN + extras_len]
        value = response[MEMCACHE_HEADER_LEN + key_len + extras_len:
                         MEMCACHE_HEADER_LEN + body_len]
        return status, value, extras

    def _make_packet(self, opcode, key, value, extras):
        """
        Construct a request packet (memcache protocol packet and UDP frame)
        with the given parameters.  Returns the request id of the packet and
        the payload.

        :param opcode: operation for the request
        :param key: key to operate on
        :param value: value of the key, if any
        :param extras: extras for the request, if any
        :returns: tuple of (request_id, packet payload)
        """
        req_id = self._udp_response_id % MAX_REQUEST_ID
        self._udp_response_id += 1
        header = struct.pack(
            REQUEST_FRAME,
            req_id, 0, 1, 0,  # UDP frame
            0x80, opcode, len(key), len(extras), 0x0, 0x0,
            len(extras) + len(key) + len(value), 0, 0)  # memcache protocol
        return req_id, ''.join((header, extras, key, value))

    def _send_and_recv(self, addr, opcode, key, value='', extras=''):
        """
        Send a memcached request and wait for the response.

        :param addr: (ip, port) of the memcached server
        :param opcode: opcode for the operation being performed
        :param key: key of the item being acted on
        :param value: value for the key, for ops that support it
        :param extras: any extras for ops that require/support it
        :raises MemcacheConnectionError: if no servers responded
        """
        for addr in self._get_servers(key):
            try:
                req_q = Queue()
                req_id, packet = self._make_packet(opcode, key, value, extras)
                self._udp_dispatch[req_id] = req_q
                try:
                    self._udp_socket.sendto(packet, addr)
                    with ResponseTimeout(self._response_timeout):
                        response = self._recv_response(req_q)
                finally:
                    # make sure the dispatch entry gets cleared
                    if req_id in self._udp_dispatch:
                        del self._udp_dispatch[req_id]
                return self._parse_response(response)
            except (Exception, ResponseTimeout) as e:
                self._exception_occurred(addr, e)
        raise MemcacheConnectionError('No Memcached connections succeeded.')

    def _send_and_recv_multi(self, server_key, messages):
        """
        Send a set of memcached requests and wait for the responses.
        They are sent pipelined one after another, then responses are gathered
        in order before returning.

        :param addr: (ip, port) of the memcached server
        :param messages: a list of tuples of (opcode, key, value, extras)
                         as per the _send_and_recv arguments.
        :raises MemcacheConnectionError: if no servers responded
        """
        for addr in self._get_servers(server_key):
            try:
                req_ids = []
                req_qs = []
                responses = []
                try:
                    for message in messages:
                        req_id, packet = self._make_packet(*message)
                        req_q = Queue()
                        self._udp_dispatch[req_id] = req_q
                        req_ids.append(req_id)
                        req_qs.append(req_q)
                        self._udp_socket.sendto(packet, addr)
                    for req_q in req_qs:
                        with ResponseTimeout(self._response_timeout):
                            responses.append(self._parse_response(
                                self._recv_response(req_q)))
                finally:
                    # make sure the dispatch entries get cleared
                    for req_id in req_ids:
                        if req_id in self._udp_dispatch:
                            del self._udp_dispatch[req_id]
                return responses
            except (Exception, ResponseTimeout) as e:
                self._exception_occurred(addr, e)
        raise MemcacheConnectionError('No Memcached connections succeeded.')

    def get(self, key):
        """
        Gets the object specified by key.  It will also unserialize the object
        before returning if it is serialized in memcache with JSON.

        :param key: key
        :returns: value of the key in memcache or None if not found
        """
        key = md5hash(key)
        try:
            status, value, extras = self._send_and_recv(OP_GET, key)
        except MemcacheConnectionError:
            return None
        if status != STATUS_NO_ERROR:
            return
        flags = struct.unpack('!I', extras)[0]
        if flags & JSON_FLAG:
            return json.loads(value)
        else:
            return value

    def get_multi(self, keys, server_key):
        """
        Gets multiple values from memcache for the given keys.

        :param keys: keys for values to be retrieved from memcache
        :param servery_key: key to use in determining which server in the ring
                            is used
        :returns: list of values
        """
        server_key = md5hash(server_key)
        messages = [(OP_GET, md5hash(key), '', '') for key in keys]
        responses = []
        try:
            results = self._send_and_recv_multi(server_key, messages)
        except MemcacheConnectionError:
            return [None for key in keys]
        for status, value, extras in results:
            if status != STATUS_NO_ERROR:
                responses.append(None)
            else:
                flags = struct.unpack('!I', extras)[0]
                if flags & JSON_FLAG:
                    responses.append(json.loads(value))
                else:
                    responses.append(value)
        return responses

    def set(self, key, value, serialize=True, time=0, min_compress_len=0):
        """
        Set a key/value pair in memcache

        :param key: key
        :param value: value
        :param serialize: if True, value is serialized with JSON before
                          sending to memcache.
        :param time: ttl in memcache, in seconds
        :min_compress_len: minimum compress length, this parameter was added
                           to keep the signature compatible with
                           python-memcached interface. This implementation
                           ignores it.
        """
        key = md5hash(key)
        time = sanitize_timeout(time)
        if serialize:
            extras = struct.pack('!II', JSON_FLAG, time)
            value = json.dumps(value)
        else:
            extras = struct.pack('!II', 0, time)
        status, value, extras = self._send_and_recv(OP_SET, key, value, extras)

    def set_multi(self, mapping, server_key, serialize=True,
                  time=0, min_compress_len=0):
        """
        Sets multiple key/value pairs in memcache.

        :param mapping: dictonary of keys and values to be set in memcache
        :param servery_key: key to use in determining which server in the ring
                            is used
        :param serialize: if True, value is serialized with JSON before sending
                          to memcache, or with pickle if configured to use
                          pickle instead of JSON (to avoid cache poisoning)
        :param time: ttl in memcache, in seconds
        :param min_compress_len: minimum compress length, this parameter was
                           added to keep the signature compatible with
                           python-memcached interface. This implementation
                           ignores it
        """
        time = sanitize_timeout(time)
        server_key = md5hash(server_key)
        messages = []
        if serialize:
            extras = struct.pack('!II', JSON_FLAG, time)
        else:
            extras = struct.pack('!II', 0, time)
        for key, value in mapping.iteritems():
            key = md5hash(key)
            if serialize:
                value = json.dumps(value)
            messages.append((OP_SET, key, value, extras))
        self._send_and_recv_multi(server_key, messages)

    def incr(self, key, delta, time=0):
        """
        Increments a key which has a numeric value by delta.
        If the key can't be found, it's added as delta or 0 if delta < 0.
        If passed a negative number, will use memcached's decr. Returns
        the int stored in memcached
        Note: The data memcached stores as the result of incr/decr is
        an unsigned int.  decr's that result in a number below 0 are
        stored as 0.

        :param key: key
        :param delta: amount to add to the value of key (or set as the value
                      if the key is not found) will be cast to an int
        :param time: ttl in memcache, in seconds
        :raises MemcacheConnectionError:
        """
        key = md5hash(key)
        time = sanitize_timeout(time)
        if delta >= 0:
            op = OP_INCREMENT
            default_value = delta
        else:
            op = OP_DECREMENT
            default_value = 0
            delta = abs(delta)
        extras = struct.pack('!QQI', delta, default_value, time)
        status, value, extras = self._send_and_recv(op, key, '', extras)
        if status == STATUS_NO_ERROR:
            return struct.unpack('!Q', value)[0]

    def decr(self, key, delta, time=0):
        """
        Decrements a key which has a numeric value by delta. Calls incr with
        -delta.

        :param key: key
        :param delta: amount to subtract to the value of key (or set the
                      value to 0 if the key is not found) will be cast to
                      an int
        :param time: ttl in memcache, in seconds
        :raises MemcacheConnectionError:
        """
        return self.incr(key, -delta, time)

    def delete(self, key):
        """
        Deletes a key/value pair from memcache.

        :param key: key to be deleted
        """
        key = md5hash(key)
        status, value, extras = self._send_and_recv(OP_DELETE, key)


class MemcacheMiddleware(object):
    """
    Caching middleware that manages caching in swift.
    Largely copied from swift.common.middleware.memcache
    """

    def __init__(self, app, conf):
        self.app = app
        memcache_servers = conf.get('memcache_servers')
        response_timeout = conf.get('memcache_response_timeout')
        bind_ip = conf.get('memcache_bind_ip')
        bind_port = conf.get('memcache_bind_port')

        if not memcache_servers:
            path = os.path.join(conf.get('swift_dir', '/etc/swift'),
                                'memcache.conf')
            memcache_conf = ConfigParser()
            if memcache_conf.read(path):
                if not memcache_servers:
                    try:
                        memcache_servers = memcache_conf.get(
                            'memcache', 'memcache_servers')
                    except (NoSectionError, NoOptionError):
                        pass
                if not response_timeout:
                    try:
                        response_timeout = memcache_conf.get(
                            'memcache', 'memcache_response_timeout')
                    except (NoSectionError, NoOptionError):
                        pass
                if not bind_ip:
                    try:
                        bind_ip = memcache_conf.get(
                            'memcache', 'memcache_bind_ip')
                    except (NoSectionError, NoOptionError):
                        pass
                if not bind_port:
                    try:
                        bind_port = memcache_conf.get(
                            'memcache', 'memcache_bind_port')
                    except (NoSectionError, NoOptionError):
                        pass

        if not memcache_servers:
            memcache_servers = '127.0.0.1'

        if bind_port:
            bind_port = int(bind_port)
        else:
            bind_port = 0

        if not bind_ip:
            bind_ip = '0.0.0.0'

        if response_timeout:
            response_timeout = float(response_timeout)
        else:
            response_timeout = RESPONSE_TIMEOUT

        self.memcache = MemcacheRing(
            [s.strip() for s in memcache_servers.split(',') if s.strip()],
            bind_ip=bind_ip, bind_port=bind_port,
            response_timeout=response_timeout)

    def __call__(self, env, start_response):
        env['swift.cache'] = self.memcache
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def cache_filter(app):
        return MemcacheMiddleware(app, conf)

    return cache_filter
