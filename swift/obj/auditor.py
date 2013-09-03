# Copyright (c) 2010-2012 OpenStack, LLC.
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
import errno
import hashlib
from swift import gettext_ as _

from eventlet import Timeout

from swift.obj import diskfile
from swift.obj import server as object_server
from swift.common.utils import get_logger, ratelimit_sleep, \
    config_true_value, dump_recon_cache, list_from_csv, json, \
    drop_buffer_cache
from swift.common.ondisk import audit_location_generator, hash_path, \
    storage_directory
from swift.common.exceptions import AuditException
from swift.common.daemon import Daemon

SLEEP_BETWEEN_AUDITS = 30


class AuditorWorker(object):
    """Walk through file system to audit object"""

    def __init__(self, conf, logger, zero_byte_only_at_fps=0):
        self.conf = conf
        self.logger = logger
        self.devices = conf.get('devices', '/srv/node')
        self.mount_check = config_true_value(conf.get('mount_check', 'true'))
        self.max_files_per_second = float(conf.get('files_per_second', 20))
        self.max_bytes_per_second = float(conf.get('bytes_per_second',
                                                   10000000))
        self.auditor_type = 'ALL'
        self.zero_byte_only_at_fps = zero_byte_only_at_fps
        if self.zero_byte_only_at_fps:
            self.max_files_per_second = float(self.zero_byte_only_at_fps)
            self.auditor_type = 'ZBF'
        self.log_time = int(conf.get('log_time', 3600))
        self.files_running_time = 0
        self.bytes_running_time = 0
        self.bytes_processed = 0
        self.total_bytes_processed = 0
        self.total_files_processed = 0
        self.passes = 0
        self.quarantines = 0
        self.errors = 0
        self.recon_cache_path = conf.get('recon_cache_path',
                                         '/var/cache/swift')
        self.rcache = os.path.join(self.recon_cache_path, "object.recon")
        self.stats_sizes = sorted(
            [int(s) for s in list_from_csv(conf.get('object_size_stats'))])
        self.stats_buckets = dict(
            [(s, 0) for s in self.stats_sizes + ['OVER']])

    def audit_all_objects(self, mode='once'):
        self.logger.info(_('Begin object audit "%s" mode (%s)') %
                         (mode, self.auditor_type))
        begin = reported = time.time()
        self.total_bytes_processed = 0
        self.total_files_processed = 0
        total_quarantines = 0
        total_errors = 0
        time_auditing = 0
        all_locs = audit_location_generator(self.devices,
                                            object_server.DATADIR, '.data',
                                            mount_check=self.mount_check,
                                            logger=self.logger)
        for path, device, partition in all_locs:
            loop_time = time.time()
            self.failsafe_object_audit(path, device, partition)
            self.logger.timing_since('timing', loop_time)
            self.files_running_time = ratelimit_sleep(
                self.files_running_time, self.max_files_per_second)
            self.total_files_processed += 1
            now = time.time()
            if now - reported >= self.log_time:
                self.logger.info(_(
                    'Object audit (%(type)s). '
                    'Since %(start_time)s: Locally: %(passes)d passed, '
                    '%(quars)d quarantined, %(errors)d errors '
                    'files/sec: %(frate).2f , bytes/sec: %(brate).2f, '
                    'Total time: %(total).2f, Auditing time: %(audit).2f, '
                    'Rate: %(audit_rate).2f') % {
                        'type': self.auditor_type,
                        'start_time': time.ctime(reported),
                        'passes': self.passes, 'quars': self.quarantines,
                        'errors': self.errors,
                        'frate': self.passes / (now - reported),
                        'brate': self.bytes_processed / (now - reported),
                        'total': (now - begin), 'audit': time_auditing,
                        'audit_rate': time_auditing / (now - begin)})
                dump_recon_cache({'object_auditor_stats_%s' %
                                  self.auditor_type: {
                                      'errors': self.errors,
                                      'passes': self.passes,
                                      'quarantined': self.quarantines,
                                      'bytes_processed': self.bytes_processed,
                                      'start_time': reported,
                                      'audit_time': time_auditing}},
                                 self.rcache, self.logger)
                reported = now
                total_quarantines += self.quarantines
                total_errors += self.errors
                self.passes = 0
                self.quarantines = 0
                self.errors = 0
                self.bytes_processed = 0
            time_auditing += (now - loop_time)
        # Avoid divide by zero during very short runs
        elapsed = (time.time() - begin) or 0.000001
        self.logger.info(_(
            'Object audit (%(type)s) "%(mode)s" mode '
            'completed: %(elapsed).02fs. Total quarantined: %(quars)d, '
            'Total errors: %(errors)d, Total files/sec: %(frate).2f , '
            'Total bytes/sec: %(brate).2f, Auditing time: %(audit).2f, '
            'Rate: %(audit_rate).2f') % {
                'type': self.auditor_type, 'mode': mode, 'elapsed': elapsed,
                'quars': total_quarantines, 'errors': total_errors,
                'frate': self.total_files_processed / elapsed,
                'brate': self.total_bytes_processed / elapsed,
                'audit': time_auditing, 'audit_rate': time_auditing / elapsed})
        if self.stats_sizes:
            self.logger.info(
                _('Object audit stats: %s') % json.dumps(self.stats_buckets))

    def record_stats(self, obj_size):
        """
        Based on config's object_size_stats will keep track of how many objects
        fall into the specified ranges. For example with the following:

        object_size_stats = 10, 100, 1024

        and your system has 3 objects of sizes: 5, 20, and 10000 bytes the log
        will look like: {"10": 1, "100": 1, "1024": 0, "OVER": 1}
        """
        for size in self.stats_sizes:
            if obj_size <= size:
                self.stats_buckets[size] += 1
                break
        else:
            self.stats_buckets["OVER"] += 1

    def failsafe_object_audit(self, path, device, partition):
        """
        Entrypoint to object_audit, with a failsafe generic exception handler.
        """
        try:
            self.object_audit(path, device, partition)
        except (Exception, Timeout):
            self.logger.increment('errors')
            self.errors += 1
            self.logger.exception(_('ERROR Trying to audit %s'), path)

    def get_data_file(self, path, device, partition):
        """
        Get a valid data file name that is auditable.

        :param path: a path to an object
        :param device: the device the path is on
        :param partition: the partition the path is on
        :returns: a valid path to a data file
        :raises: AuditException for inconsistent data states
        """
        datadir = os.path.dirname(path)
        data_file, meta_file, ts_file = diskfile.get_ondisk_file(datadir)
        if not data_file:
            # TODO(portante): the audit location generator gave us a path
            # to a .data file, but according to the current state of the
            # on-disk files in data directory, the file is considered
            # deleted or has been removed entirely. Perhaps we should be
            # calling hash_cleanup_listdir() here instead.
            return None, None, None
        if path != data_file:
            # TODO(portante): The audit location generator gave us a path
            # to a .data file that is not considered the live data file
            # for this object. We should probably invoke
            # hash_cleanup_listdir() here instead.
            return None, None, None
        try:
            metadata = diskfile.read_metadata(data_file)
        except (Exception, Timeout) as exc:
            raise AuditException(
                _('Error when reading metadata: %s') % exc)
        try:
            name = metadata['name']
            _junk, account, container, obj = name.split('/', 3)
            content_length = metadata['Content-Length']
            content_length = int(content_length)
            etag = metadata["ETag"]
        except (KeyError, ValueError):
            raise AuditException(
                _("Unable to fetch required metadata for object"))
        name_hash = hash_path(account, container, obj)
        computed_datadir = os.path.join(
            self.devices, device, storage_directory(
                object_server.DATADIR, partition, name_hash))
        if computed_datadir != datadir:
            raise AuditException(
                _("Computed data directory, %s,"
                  " does not match object's") % (
                      computed_datadir))
        return data_file, content_length, etag

    def get_and_verify_size(self, data_file, fp, content_length):
        """
        Verify the file size matches the given metadata content-length,
        returning it on success.

        :param data_file: full path of the .data file on-disk
        :param fp: open file pointer for the data_file
        :param content_length: content length value to check against file
                               system recorded length
        :returns: the size of the file that matches the content-length
        :raises: AuditException if the fstat() system call fails, or if the
                 on-disk size does not match the content-length metdata.
        """
        try:
            # Don't stat by name to avoid possible race conditions.
            stats = os.fstat(fp.fileno())
        except OSError as err:
            raise AuditException(str(err))
        else:
            if not stats:
                raise AuditException(
                    _('Unable to retrieve stat of object'))
        obj_size = stats.st_size
        if obj_size != content_length:
            raise AuditException(
                _("On-disk size, %s, != metadata's size, %s") % (
                    obj_size, content_length))
        return obj_size

    def verify_etag(self, data_file, fp, curr_etag):
        """
        Read the entire data file calculating the MD5 hash and comparing
        against the current ETag.

        :param data_file: full path of the .data file on-disk
        :param fp: open file pointer for the data_file
        :param curr_etag: the ETag stored in the data file's metadata
        :raises: AuditException if the ETag does not match the calculated MD5
                 hash
        """
        etag = hashlib.md5()
        dropped_cache = 0
        read = 0
        while True:
            chunk = fp.read(64 * 1024)
            if chunk:
                etag.update(chunk)
                chunk_len = len(chunk)
                read += chunk_len
                if read - dropped_cache > (1024 * 1024):
                    drop_buffer_cache(fp.fileno(), dropped_cache,
                                      read - dropped_cache)
                self.bytes_running_time = ratelimit_sleep(
                    self.bytes_running_time,
                    self.max_bytes_per_second,
                    incr_by=chunk_len)
                self.bytes_processed += chunk_len
                self.total_bytes_processed += chunk_len
            else:
                break
        if etag.hexdigest() != curr_etag:
            raise AuditException(
                _("ETag and object's MD5 do not match"))

    def object_audit(self, path, device, partition):
        """
        Audits the given object path.

        :param path: a path to an object
        :param device: the device the path is on
        :param partition: the partition the path is on
        """
        try:
            data_file, content_length, curr_etag = self.get_data_file(
                path, device, partition)
            if not data_file:
                self.logger.info(_('INFO Nothing to audit at %(datadir)s'),
                                 {'datadir': os.path.basename(path)})
                return
            try:
                with open(data_file, "r") as fp:
                    obj_size = self.get_and_verify_size(
                        data_file, fp, content_length)
                    if self.stats_sizes:
                        self.record_stats(obj_size)
                    if self.zero_byte_only_at_fps and obj_size:
                        self.passes += 1
                        return
                    self.verify_etag(data_file, fp, curr_etag)
            except IOError as err:
                if err.errno == errno.ENOENT:
                    return
                raise AuditException(
                    _("Unable to open, stat, or read object: %(err)s") % (
                        {"err": err}))
        except AuditException as err:
            self.logger.increment('quarantines')
            self.quarantines += 1
            self.logger.error(_('ERROR Object %(obj)s failed audit and will '
                                'be quarantined: %(err)s'),
                              {'obj': path, 'err': err})
            diskfile.quarantine_renamer(
                os.path.join(self.devices, device), path)
            return
        self.passes += 1


class ObjectAuditor(Daemon):
    """Audit objects."""

    def __init__(self, conf, **options):
        self.conf = conf
        self.logger = get_logger(conf, log_route='object-auditor')
        self.conf_zero_byte_fps = int(
            conf.get('zero_byte_files_per_second', 50))

    def _sleep(self):
        time.sleep(SLEEP_BETWEEN_AUDITS)

    def run_forever(self, *args, **kwargs):
        """Run the object audit until stopped."""
        # zero byte only command line option
        zbo_fps = kwargs.get('zero_byte_fps', 0)
        if zbo_fps:
            # only start parent
            parent = True
        else:
            parent = os.fork()  # child gets parent = 0
        kwargs = {'mode': 'forever'}
        if parent:
            kwargs['zero_byte_fps'] = zbo_fps or self.conf_zero_byte_fps
        while True:
            try:
                self.run_once(**kwargs)
            except (Exception, Timeout):
                self.logger.exception(_('ERROR auditing'))
            self._sleep()

    def run_once(self, *args, **kwargs):
        """Run the object audit once."""
        mode = kwargs.get('mode', 'once')
        zero_byte_only_at_fps = kwargs.get('zero_byte_fps', 0)
        worker = AuditorWorker(self.conf, self.logger,
                               zero_byte_only_at_fps=zero_byte_only_at_fps)
        worker.audit_all_objects(mode=mode)
