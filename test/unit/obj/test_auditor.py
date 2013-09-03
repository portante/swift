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

from test import unit
import unittest
import mock
import os
import time
import errno
from shutil import rmtree
from hashlib import md5
from tempfile import mkdtemp
from test.unit import FakeLogger
from swift.obj import auditor
from swift.obj.diskfile import DiskFile, write_metadata, invalidate_hash, \
    read_metadata
from swift.obj.server import DATADIR
from swift.common.utils import mkdirs
from swift.common.ondisk import hash_path, normalize_timestamp, \
    storage_directory


class TestAuditor(unittest.TestCase):

    def setUp(self):
        self.testdir = os.path.join(mkdtemp(), 'tmp_test_object_auditor')
        self.devices = os.path.join(self.testdir, 'node')
        self.logger = FakeLogger()
        rmtree(self.testdir, ignore_errors=1)
        mkdirs(os.path.join(self.devices, 'sda'))
        self.objects = os.path.join(self.devices, 'sda', 'objects')

        os.mkdir(os.path.join(self.devices, 'sdb'))
        self.objects_2 = os.path.join(self.devices, 'sdb', 'objects')

        os.mkdir(self.objects)
        self.parts = {}
        for part in ['0', '1', '2', '3']:
            self.parts[part] = os.path.join(self.objects, part)
            os.mkdir(os.path.join(self.objects, part))

        self.conf = dict(
            devices=self.devices,
            mount_check='false',
            object_size_stats='10,100,1024,10240')
        self.disk_file = DiskFile(self.devices, 'sda', '0', 'a', 'c', 'o',
                                  self.logger)

    def tearDown(self):
        rmtree(os.path.dirname(self.testdir), ignore_errors=1)
        unit.xattr_data = {}

    def test_object_audit_extra_data(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        data = '0' * 1024
        etag = md5()
        with self.disk_file.create() as writer:
            writer.write(data)
            etag.update(data)
            etag = etag.hexdigest()
            timestamp = normalize_timestamp(time.time())
            metadata = {
                'ETag': etag,
                'X-Timestamp': timestamp,
                'Content-Length': str(os.fstat(writer.fd).st_size),
            }
            writer.put(metadata)
            pre_quarantines = auditor_worker.quarantines

            auditor_worker.object_audit(
                os.path.join(self.disk_file.datadir, timestamp + '.data'),
                'sda', '0')
            self.assertEquals(auditor_worker.quarantines, pre_quarantines)

            os.write(writer.fd, 'extra_data')
            auditor_worker.object_audit(
                os.path.join(self.disk_file.datadir, timestamp + '.data'),
                'sda', '0')
            self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_audit_diff_data(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        data = '0' * 1024
        etag = md5()
        timestamp = normalize_timestamp(time.time())
        with self.disk_file.create() as writer:
            writer.write(data)
            etag.update(data)
            etag = etag.hexdigest()
            metadata = {
                'ETag': etag,
                'X-Timestamp': timestamp,
                'Content-Length': str(os.fstat(writer.fd).st_size),
            }
            writer.put(metadata)

        pre_quarantines = auditor_worker.quarantines

        # remake so it will have metadata
        self.disk_file = DiskFile(self.devices, 'sda', '0', 'a', 'c', 'o',
                                  self.logger)

        auditor_worker.object_audit(
            os.path.join(self.disk_file.datadir, timestamp + '.data'),
            'sda', '0')
        self.assertEquals(auditor_worker.quarantines, pre_quarantines)
        etag = md5()
        etag.update('1' + '0' * 1023)
        etag = etag.hexdigest()
        metadata['ETag'] = etag

        with self.disk_file.create() as writer:
            writer.write(data)
            writer.put(metadata)

        auditor_worker.object_audit(
            os.path.join(self.disk_file.datadir, timestamp + '.data'),
            'sda', '0')
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_audit_no_meta(self):
        timestamp = normalize_timestamp(time.time())
        path = os.path.join(self.disk_file.datadir, timestamp + '.data')
        mkdirs(self.disk_file.datadir)
        fp = open(path, 'w')
        fp.write('0' * 1024)
        fp.close()
        invalidate_hash(os.path.dirname(self.disk_file.datadir))
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        auditor_worker.object_audit(
            os.path.join(self.disk_file.datadir, timestamp + '.data'),
            'sda', '0')
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_audit_will_not_swallow_errors_in_tests(self):
        timestamp = str(normalize_timestamp(time.time()))
        path = os.path.join(self.disk_file.datadir, timestamp + '.data')
        mkdirs(self.disk_file.datadir)
        with open(path, 'w') as f:
            write_metadata(f, {'name': '/a/c/o'})
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)

        def blowup(*args):
            raise NameError('tpyo')

        with mock.patch('swift.obj.diskfile.get_ondisk_file', blowup):
            self.assertRaises(NameError, auditor_worker.object_audit,
                              path, 'sda', '0')

    def test_failsafe_object_audit_will_swallow_errors_in_tests(self):
        timestamp = str(normalize_timestamp(time.time()))
        path = os.path.join(self.disk_file.datadir, timestamp + '.data')
        mkdirs(self.disk_file.datadir)
        with open(path, 'w') as f:
            write_metadata(f, {'name': '/a/c/o'})
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)

        def blowup(*args):
            raise NameError('tpyo')

        with mock.patch('swift.obj.diskfile.get_ondisk_file', blowup):
            auditor_worker.failsafe_object_audit(path, 'sda', '0')
        self.assertEquals(auditor_worker.errors, 1)

    def test_object_audit_path_gone(self):
        timestamp = normalize_timestamp(time.time())
        path = os.path.join(self.disk_file.datadir, timestamp + '.data')
        mkdirs(self.disk_file.datadir)
        invalidate_hash(os.path.dirname(self.disk_file.datadir))
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        auditor_worker.object_audit(path, 'sda', '0')
        self.assertEquals(auditor_worker.quarantines, pre_quarantines)

    def test_object_audit_path_old(self):
        t0 = time.time()
        timestamp = normalize_timestamp(t0)
        path = os.path.join(self.disk_file.datadir, timestamp + '.data')
        mkdirs(self.disk_file.datadir)
        fp = open(path, 'w')
        fp.write('0' * 1024)
        fp.close()
        invalidate_hash(os.path.dirname(self.disk_file.datadir))
        oldtimestamp = normalize_timestamp(t0 - 1)
        oldpath = os.path.join(self.disk_file.datadir, oldtimestamp + '.data')
        fp = open(oldpath, 'w')
        fp.write('0' * 1024)
        fp.close()
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        auditor_worker.object_audit(
            os.path.join(self.disk_file.datadir, oldtimestamp + '.data'),
            'sda', '0')
        self.assertEquals(auditor_worker.quarantines, pre_quarantines)

    def _create_object(self, size, etag_suffix='', ch='0', noetag=False,
                       extra=''):
        timestamp = normalize_timestamp(time.time())
        data = ch * size
        etag = md5()
        with self.disk_file.create() as writer:
            writer.write(data)
            etag.update(data)
            etag = etag.hexdigest()
            metadata = {
                'ETag': etag + etag_suffix,
                'X-Timestamp': timestamp,
                'Content-Length': str(os.fstat(writer.fd).st_size),
            }
            if noetag:
                del metadata['ETag']
            writer.put(metadata)
            if extra:
                os.write(writer.fd, extra)

    def test_generic_exception_handling(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_errors = auditor_worker.errors
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024)
        with mock.patch('swift.obj.diskfile.get_ondisk_file',
                        lambda *_: 1 / 0):
            auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines)
        self.assertEquals(auditor_worker.errors, pre_errors + 1)

    def test_object_run_once_pass(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        auditor_worker.log_time = 0
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024)
        auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines)
        self.assertEquals(auditor_worker.stats_buckets[1024], 1)
        self.assertEquals(auditor_worker.stats_buckets[10240], 0)

    def test_object_run_once_bad_etag(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        # This also exercises the drop_buffer_cache path
        self._create_object((1024 * 1024) + 1024, etag_suffix='bad')
        auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_run_once_missing_etag(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024, noetag=True)
        auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_run_once_open_enoent(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024)

        def mock_get_data_file(path, device, partition):
            os.unlink(path)
            return path, None, None

        auditor_worker.get_data_file = mock_get_data_file
        auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines)

    def test_object_run_once_open_ioerror(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024)

        def mock_open(*args, **kwargs):
            ioerr = IOError()
            ioerr.errno = errno.EPERM
            raise ioerr

        orig_open = auditor.__builtins__['open']
        try:
            auditor.__builtins__['open'] = mock_open
            auditor_worker.audit_all_objects()
        finally:
            auditor.__builtins__['open'] = orig_open
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_run_once_fstat_oserror(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024)

        def mock_fstat(*args, **kwargs):
            raise OSError("mocked")

        with mock.patch("os.fstat", mock_fstat):
            auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_run_once_fstat_none(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024)

        def mock_fstat(*args, **kwargs):
            return None

        with mock.patch("os.fstat", mock_fstat):
            auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_run_once_pass_no_stats_sizes(self):
        conf = dict(
            devices=self.devices,
            mount_check='false')
        auditor_worker = auditor.AuditorWorker(conf, self.logger)
        self.assertEquals(auditor_worker.stats_sizes, [])
        self.assertEquals(auditor_worker.stats_buckets['OVER'], 0)
        auditor_worker.log_time = 0
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024)
        auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines)
        # Because we don't have any sizes to record, we don't record anything.
        self.assertEquals(auditor_worker.stats_buckets['OVER'], 0)

    def test_object_run_once_pass_one_stats_size(self):
        conf = dict(
            devices=self.devices,
            mount_check='false',
            object_size_stats='10')
        auditor_worker = auditor.AuditorWorker(conf, self.logger)
        auditor_worker.log_time = 0
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024)
        auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines)
        self.assertEquals(auditor_worker.stats_buckets['OVER'], 1)

    def test_object_run_once_no_sda(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        self._create_object(1024, extra='extra_data')
        auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_run_once_multi_devices(self):
        auditor_worker = auditor.AuditorWorker(self.conf, self.logger)
        pre_quarantines = auditor_worker.quarantines
        self._create_object(10)
        auditor_worker.audit_all_objects()

        self.disk_file = DiskFile(self.devices, 'sdb', '0', 'a', 'c',
                                  'ob', self.logger)
        self._create_object(10, ch='1', extra='extra_data')
        auditor_worker.audit_all_objects()
        self.assertEquals(auditor_worker.quarantines, pre_quarantines + 1)

    def test_object_run_fast_track_non_zero(self):
        auditor_worker = auditor.ObjectAuditor(self.conf)
        auditor_worker.log_time = 0
        data = '0' * 1024
        etag = md5()
        with self.disk_file.create() as writer:
            writer.write(data)
            etag.update(data)
            etag = etag.hexdigest()
            metadata = {
                'ETag': etag,
                'X-Timestamp': normalize_timestamp(time.time()),
                'Content-Length': str(os.fstat(writer.fd).st_size),
            }
            writer.put(metadata)
            etag = md5()
            etag.update('1' + '0' * 1023)
            etag = etag.hexdigest()
            metadata['ETag'] = etag
            write_metadata(writer.fd, metadata)

        quarantine_path = os.path.join(self.devices,
                                       'sda', 'quarantined', 'objects')
        auditor_worker.run_once(zero_byte_fps=50)
        self.assertFalse(os.path.isdir(quarantine_path))
        auditor_worker.run_once()
        self.assertTrue(os.path.isdir(quarantine_path))

    def test_object_run_name_does_not_match(self):
        auditor_worker = auditor.ObjectAuditor(self.conf)
        auditor_worker.log_time = 0
        data = '0' * 1024
        etag = md5()
        with self.disk_file.create() as writer:
            writer.write(data)
            etag.update(data)
            etag = etag.hexdigest()
            metadata = {
                'ETag': etag,
                'X-Timestamp': normalize_timestamp(time.time()),
                'Content-Length': str(os.fstat(writer.fd).st_size),
            }
            writer.put(metadata)
            metadata = read_metadata(writer.fd)
            metadata['name'] = "/a/c/doesnotexist"
            write_metadata(writer.fd, metadata)

        quarantine_path = os.path.join(self.devices,
                                       'sda', 'quarantined', 'objects')
        auditor_worker.run_once()
        self.assertTrue(os.path.isdir(quarantine_path))

    def setup_bad_zero_byte(self, with_ts=False):
        self.auditor = auditor.ObjectAuditor(self.conf)
        self.auditor.log_time = 0
        ts_file_path = ''
        if with_ts:
            name_hash = hash_path('a', 'c', 'o')
            dir_path = os.path.join(
                self.devices, 'sda',
                storage_directory(DATADIR, '0', name_hash))
            ts_file_path = os.path.join(dir_path, '99999.ts')
            if not os.path.exists(dir_path):
                mkdirs(dir_path)
            fp = open(ts_file_path, 'w')
            fp.close()

        etag = md5()
        with self.disk_file.create() as writer:
            etag = etag.hexdigest()
            metadata = {
                'ETag': etag,
                'X-Timestamp': normalize_timestamp(time.time()),
                'Content-Length': 10,
            }
            writer.put(metadata)
            etag = md5()
            etag = etag.hexdigest()
            metadata['ETag'] = etag
            write_metadata(writer.fd, metadata)
        if self.disk_file.data_file:
            return self.disk_file.data_file
        return ts_file_path

    def test_object_run_fast_track_all(self):
        self.setup_bad_zero_byte()
        self.auditor.run_once()
        quarantine_path = os.path.join(self.devices,
                                       'sda', 'quarantined', 'objects')
        self.assertTrue(os.path.isdir(quarantine_path))

    def test_object_run_fast_track_zero(self):
        self.setup_bad_zero_byte()
        self.auditor.run_once(zero_byte_fps=50)
        quarantine_path = os.path.join(self.devices,
                                       'sda', 'quarantined', 'objects')
        self.assertTrue(os.path.isdir(quarantine_path))

    def test_with_tombstone(self):
        ts_file_path = self.setup_bad_zero_byte(with_ts=True)
        self.auditor.run_once()
        self.assertTrue(ts_file_path.endswith('ts'))
        self.assertTrue(os.path.exists(ts_file_path))

    def test_sleeper(self):
        auditor.SLEEP_BETWEEN_AUDITS = 0.10
        my_auditor = auditor.ObjectAuditor(self.conf)
        start = time.time()
        my_auditor._sleep()
        delta_t = time.time() - start
        self.assert_(delta_t > 0.08)
        self.assert_(delta_t < 0.12)

    def test_object_run_fast_track_zero_check_closed(self):
        rat = [False]
        fstat = os.fstat

        def mock_fstat(*args, **kwargs):
            rat[0] = True
            return fstat(*args, **kwargs)

        self.setup_bad_zero_byte()
        with mock.patch("os.fstat", mock_fstat):
            self.auditor.run_once(zero_byte_fps=50)
            quarantine_path = os.path.join(self.devices,
                                           'sda', 'quarantined', 'objects')
            self.assertTrue(os.path.isdir(quarantine_path))
            self.assertTrue(rat[0])

    def test_run_forever(self):

        class StopForever(Exception):
            pass

        class ObjectAuditorMock(object):
            check_args = ()
            check_kwargs = {}
            raise_exception = 0
            fork_called = 0
            fork_res = 0
            fake_logger = FakeLogger()

            def mock_run_once(self, *args, **kwargs):
                self.check_args = args
                self.check_kwargs = kwargs
                if self.raise_exception:
                    raise Exception('run once exception')

            def mock_sleep(self):
                raise StopForever('stop')

            def mock_fork(self):
                self.fork_called += 1
                return self.fork_res

        my_auditor = auditor.ObjectAuditor(dict(devices=self.devices,
                                                mount_check='false',
                                                zero_byte_files_per_second=89))
        mocker = ObjectAuditorMock()
        my_auditor.run_once = mocker.mock_run_once
        my_auditor._sleep = mocker.mock_sleep
        my_auditor.logger = mocker.fake_logger
        with mock.patch("os.fork", mocker.mock_fork):
            self.assertRaises(StopForever,
                              my_auditor.run_forever, zero_byte_fps=50)
            self.assertEquals(mocker.check_kwargs['zero_byte_fps'], 50)
            self.assertEquals(mocker.fork_called, 0)

            self.assertRaises(StopForever, my_auditor.run_forever)
            self.assertEquals(mocker.fork_called, 1)
            self.assertEquals(mocker.check_args, ())

            mocker.fork_res = 1
            self.assertRaises(StopForever, my_auditor.run_forever)
            self.assertEquals(mocker.fork_called, 2)
            self.assertEquals(mocker.check_kwargs['zero_byte_fps'], 89)

            mocker.raise_exception = 1
            self.assertRaises(StopForever, my_auditor.run_forever)
            self.assertEquals(mocker.fork_called, 3)
            self.assertEquals(mocker.check_args, ())
            self.assertEquals(mocker.fake_logger.log_dict['exception'][0][2],
                              'run once exception')

if __name__ == '__main__':
    unittest.main()
