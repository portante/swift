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

""" Disk File Interface for Swift Object Server"""

from __future__ import with_statement
import cPickle as pickle
import errno
import os
import time
import uuid
import hashlib
import logging
import traceback
from os.path import basename, dirname, exists, getmtime, join
from tempfile import mkstemp
from contextlib import contextmanager

from xattr import getxattr, setxattr
from eventlet import Timeout

from swift import gettext_ as _
from swift.common.utils import mkdirs, renamer, fallocate, fsync, fdatasync, \
    drop_buffer_cache, ThreadPool, lock_path, write_pickle
from swift.common.ondisk import hash_path, normalize_timestamp, \
    storage_directory, Devices
from swift.common.exceptions import DiskFileQuarantined, DiskFileNotExist, \
    DiskFileCollision, DiskFileNoSpace, DiskFileDeviceUnavailable, \
    DiskFileDeleted, DiskFileError, DiskFileNotOpen, PathNotDir
from swift.common.swob import multi_range_iterator


PICKLE_PROTOCOL = 2
ONE_WEEK = 604800
HASH_FILE = 'hashes.pkl'
METADATA_KEY = 'user.swift.metadata'
# These are system-set metadata keys that cannot be changed with a POST.
# They should be lowercase.
DATAFILE_SYSTEM_META = set('content-length content-type deleted etag'.split())
DATADIR = 'objects'
ASYNCDIR = 'async_pending'


def read_metadata(fd):
    """
    Helper function to read the pickled metadata from an object file.

    :param fd: file descriptor to load the metadata from

    :returns: dictionary of metadata
    """
    metadata = ''
    key = 0
    try:
        while True:
            metadata += getxattr(fd, '%s%s' % (METADATA_KEY, (key or '')))
            key += 1
    except IOError:
        pass
    return pickle.loads(metadata)


def write_metadata(fd, metadata):
    """
    Helper function to write pickled metadata for an object file.

    :param fd: file descriptor to write the metadata
    :param metadata: metadata to write
    """
    metastr = pickle.dumps(metadata, PICKLE_PROTOCOL)
    key = 0
    while metastr:
        setxattr(fd, '%s%s' % (METADATA_KEY, key or ''), metastr[:254])
        metastr = metastr[254:]
        key += 1


def quarantine_renamer(device_path, corrupted_file_path):
    """
    In the case that a file is corrupted, move it to a quarantined
    area to allow replication to fix it.

    :params device_path: The path to the device the corrupted file is on.
    :params corrupted_file_path: The path to the file you want quarantined.

    :returns: path (str) of directory the file was moved to
    :raises OSError: re-raises non errno.EEXIST / errno.ENOTEMPTY
                     exceptions from rename
    """
    from_dir = dirname(corrupted_file_path)
    to_dir = join(device_path, 'quarantined', 'objects', basename(from_dir))
    invalidate_hash(dirname(from_dir))
    try:
        renamer(from_dir, to_dir)
    except OSError as e:
        if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise
        to_dir = "%s-%s" % (to_dir, uuid.uuid4().hex)
        renamer(from_dir, to_dir)
    return to_dir


def hash_cleanup_listdir(hsh_path, reclaim_age=ONE_WEEK):
    """
    List contents of a hash directory and clean up any old files.

    :param hsh_path: object hash path
    :param reclaim_age: age in seconds at which to remove tombstones
    :returns: list of files remaining in the directory, reverse sorted
    """
    files = os.listdir(hsh_path)
    if len(files) == 1:
        if files[0].endswith('.ts'):
            # remove tombstones older than reclaim_age
            ts = files[0].rsplit('.', 1)[0]
            if (time.time() - float(ts)) > reclaim_age:
                os.unlink(join(hsh_path, files[0]))
                files.remove(files[0])
    elif files:
        files.sort(reverse=True)
        meta = data = tomb = None
        for filename in list(files):
            if not meta and filename.endswith('.meta'):
                meta = filename
            if not data and filename.endswith('.data'):
                data = filename
            if not tomb and filename.endswith('.ts'):
                tomb = filename
            if (filename < tomb or       # any file older than tomb
                filename < data or       # any file older than data
                (filename.endswith('.meta') and
                 filename < meta)):      # old meta
                os.unlink(join(hsh_path, filename))
                files.remove(filename)
    return files


def hash_suffix(path, reclaim_age):
    """
    Performs reclamation and returns an md5 of all (remaining) files.

    :param reclaim_age: age in seconds at which to remove tombstones
    :raises PathNotDir: if given path is not a valid directory
    :raises OSError: for non-ENOTDIR errors
    """
    md5 = hashlib.md5()
    try:
        path_contents = sorted(os.listdir(path))
    except OSError as err:
        if err.errno in (errno.ENOTDIR, errno.ENOENT):
            raise PathNotDir()
        raise
    for hsh in path_contents:
        hsh_path = join(path, hsh)
        try:
            files = hash_cleanup_listdir(hsh_path, reclaim_age)
        except OSError as err:
            if err.errno == errno.ENOTDIR:
                partition_path = dirname(path)
                objects_path = dirname(partition_path)
                device_path = dirname(objects_path)
                quar_path = quarantine_renamer(device_path, hsh_path)
                logging.exception(
                    _('Quarantined %s to %s because it is not a directory') %
                    (hsh_path, quar_path))
                continue
            raise
        if not files:
            os.rmdir(hsh_path)
        for filename in files:
            md5.update(filename)
    try:
        os.rmdir(path)
    except OSError:
        pass
    return md5.hexdigest()


def invalidate_hash(suffix_dir):
    """
    Invalidates the hash for a suffix_dir in the partition's hashes file.

    :param suffix_dir: absolute path to suffix dir whose hash needs
                       invalidating
    """

    suffix = basename(suffix_dir)
    partition_dir = dirname(suffix_dir)
    hashes_file = join(partition_dir, HASH_FILE)
    with lock_path(partition_dir):
        try:
            with open(hashes_file, 'rb') as fp:
                hashes = pickle.load(fp)
            if suffix in hashes and not hashes[suffix]:
                return
        except Exception:
            return
        hashes[suffix] = None
        write_pickle(hashes, hashes_file, partition_dir, PICKLE_PROTOCOL)


def get_hashes(partition_dir, recalculate=None, do_listdir=False,
               reclaim_age=ONE_WEEK):
    """
    Get a list of hashes for the suffix dir.  do_listdir causes it to mistrust
    the hash cache for suffix existence at the (unexpectedly high) cost of a
    listdir.  reclaim_age is just passed on to hash_suffix.

    :param partition_dir: absolute path of partition to get hashes for
    :param recalculate: list of suffixes which should be recalculated when got
    :param do_listdir: force existence check for all hashes in the partition
    :param reclaim_age: age at which to remove tombstones

    :returns: tuple of (number of suffix dirs hashed, dictionary of hashes)
    """

    hashed = 0
    hashes_file = join(partition_dir, HASH_FILE)
    modified = False
    force_rewrite = False
    hashes = {}
    mtime = -1

    if recalculate is None:
        recalculate = []

    try:
        with open(hashes_file, 'rb') as fp:
            hashes = pickle.load(fp)
        mtime = getmtime(hashes_file)
    except Exception:
        do_listdir = True
        force_rewrite = True
    if do_listdir:
        for suff in os.listdir(partition_dir):
            if len(suff) == 3:
                hashes.setdefault(suff, None)
        modified = True
    hashes.update((hash_, None) for hash_ in recalculate)
    for suffix, hash_ in hashes.items():
        if not hash_:
            suffix_dir = join(partition_dir, suffix)
            try:
                hashes[suffix] = hash_suffix(suffix_dir, reclaim_age)
                hashed += 1
            except PathNotDir:
                del hashes[suffix]
            except OSError:
                logging.exception(_('Error hashing suffix'))
            modified = True
    if modified:
        with lock_path(partition_dir):
            if force_rewrite or not exists(hashes_file) or \
                    getmtime(hashes_file) == mtime:
                write_pickle(
                    hashes, hashes_file, partition_dir, PICKLE_PROTOCOL)
                return hashed, hashes
        return get_hashes(partition_dir, recalculate, do_listdir,
                          reclaim_age)
    else:
        return hashed, hashes


class DiskFileManager(object):
    """
    Management class for devices, providing common place for shared parameters
    and methods not provided by the DiskFile class (which primarily services
    the object server REST API layer).

    The get_diskfile() method is how this implementation creates a DiskFile
    object.

    TODO(portante): Not sure what the right name to recommend here

    :param conf: caller provided configuration object
    :param logger: caller provided logger
    """
    def __init__(self, conf, logger):
        self.devices = Devices(conf)
        self.logger = logger
        self.disk_chunk_size = int(conf.get('disk_chunk_size', 65536))
        self.keep_cache_size = int(conf.get('keep_cache_size', 5242880))
        self.bytes_per_sync = int(conf.get('mb_per_sync', 512)) * 1024 * 1024

    def pickle_async_update(self, device, account, container, obj, data,
                            timestamp):
        device_path = self.devices.construct_dev_path(device)
        async_dir = os.path.join(device_path, ASYNCDIR)
        ohash = hash_path(account, container, obj)
        self.devices.threadpools[device].run_in_thread(
            write_pickle,
            data,
            os.path.join(async_dir, ohash[-3:], ohash + '-' +
                         normalize_timestamp(timestamp)),
            os.path.join(device_path, 'tmp'))
        self.logger.increment('async_pendings')

    def get_diskfile(self, device, partition, account, container, obj,
                     **kwargs):
        dev_path = self.devices.get_dev_path(device)
        if not dev_path:
            raise DiskFileDeviceUnavailable()
        return DiskFile(self, dev_path, self.devices.threadpools[device],
                        partition, account, container, obj, **kwargs)

    def get_hashes(self, device, partition, suffix):
        dev_path = self.devices.get_dev_path(device)
        if not dev_path:
            raise DiskFileDeviceUnavailable()
        partition_path = os.path.join(dev_path, DATADIR, partition)
        if not os.path.exists(partition_path):
            mkdirs(partition_path)
        suffixes = suffix.split('-') if suffix else []
        _junk, hashes = self.devices.threadpools[device].force_run_in_thread(
            get_hashes, partition_path, recalculate=suffixes)
        return hashes


class DiskFileWriter(object):
    """
    Encapsulation of the write context for servicing PUT REST API
    requests. Serves as the context manager object for DiskFile's create()
    method.
    """
    def __init__(self, name, datadir, fd, tmppath, bytes_per_sync, threadpool):
        self.name = name
        self.datadir = datadir
        self.fd = fd
        self.tmppath = tmppath
        self.bytes_per_sync = bytes_per_sync
        self.threadpool = threadpool
        self.upload_size = 0
        self.last_sync = 0
        self._extension = '.data'

    def write(self, chunk):
        """
        Write a chunk of data into the temporary file.

        :param chunk: the chunk of data to write as a string object
        """

        def _write_entire_chunk(chunk):
            while chunk:
                written = os.write(self.fd, chunk)
                self.upload_size += written
                chunk = chunk[written:]

        self.threadpool.run_in_thread(_write_entire_chunk, chunk)

        # For large files sync every 512MB (by default) written
        diff = self.upload_size - self.last_sync
        if diff >= self.bytes_per_sync:
            self.threadpool.force_run_in_thread(fdatasync, self.fd)
            drop_buffer_cache(self.fd, self.last_sync, diff)
            self.last_sync = self.upload_size

    def _finalize_put(self, metadata, target_path):
        # Write the metadata before calling fsync() so that both data and
        # metadata are flushed to disk.
        write_metadata(self.fd, metadata)
        # We call fsync() before calling drop_cache() to lower the amount of
        # redundant work the drop cache code will perform on the pages (now
        # that after fsync the pages will be all clean).
        fsync(self.fd)
        # From the Department of the Redundancy Department, make sure we call
        # drop_cache() after fsync() to avoid redundant work (pages all
        # clean).
        drop_buffer_cache(self.fd, 0, self.upload_size)
        invalidate_hash(dirname(self.datadir))
        # After the rename completes, this object will be available for other
        # requests to reference.
        renamer(self.tmppath, target_path)
        hash_cleanup_listdir(self.datadir)

    def put(self, metadata):
        """
        Finalize writing the file on disk, and renames it from the temp file
        to the real location.  This should be called after the data has been
        written to the temp file.

        :param metadata: dictionary of metadata to be written
        :param extension: extension to be used when making the file
        """
        if not self.tmppath:
            raise ValueError("tmppath is unusable.")
        timestamp = normalize_timestamp(metadata['X-Timestamp'])
        metadata['name'] = self.name
        target_path = join(self.datadir, timestamp + self._extension)

        self.threadpool.force_run_in_thread(
            self._finalize_put, metadata, target_path)


class DiskFileReader(object):
    """
    Encapsulation of the read context for servicing GET REST API
    requests. Serves as the context manager object for DiskFile's reader()
    method.

    :param disk_file: DiskFile object associated with this reader
    :param fp: open file object pointer reference
    :param iter_hook: called when __iter__ returns a chunk
    :param keep_cache: should resulting reads be kept in the buffer cache
    """
    def __init__(self, fp, obj_size, etag, data_file, threadpool,
                 disk_chunk_size, keep_cache_size, device_path, logger,
                 iter_hook=None, keep_cache=False):
        self.fp = fp
        self._obj_size = obj_size
        self.etag = etag
        self.data_file = data_file
        self.threadpool = threadpool
        self.disk_chunk_size = disk_chunk_size
        self.device_path = device_path
        self.logger = logger
        self.iter_hook = iter_hook
        if keep_cache:
            # Caller suggests we keep this in cache, only do it if the
            # object's size is less than the maximum.
            self.keep_cache = obj_size < keep_cache_size
        else:
            self.keep_cache = False
        #
        self.iter_etag = None
        self.bytes_read = 0
        self.started_at_0 = False
        self.read_to_eof = False
        self.suppress_file_closing = False
        self.was_quarantined = ''

    def __iter__(self):
        """Returns an iterator over the data file."""
        try:
            dropped_cache = 0
            self.bytes_read = 0
            self.started_at_0 = False
            self.read_to_eof = False
            if self.fp.tell() == 0:
                self.started_at_0 = True
                self.iter_etag = hashlib.md5()
            while True:
                chunk = self.threadpool.run_in_thread(
                    self.fp.read, self.disk_chunk_size)
                if chunk:
                    if self.iter_etag:
                        self.iter_etag.update(chunk)
                    self.bytes_read += len(chunk)
                    if self.bytes_read - dropped_cache > (1024 * 1024):
                        self._drop_cache(self.fp.fileno(), dropped_cache,
                                         self.bytes_read - dropped_cache)
                        dropped_cache = self.bytes_read
                    yield chunk
                    if self.iter_hook:
                        self.iter_hook()
                else:
                    self.read_to_eof = True
                    self._drop_cache(self.fp.fileno(), dropped_cache,
                                     self.bytes_read - dropped_cache)
                    break
        finally:
            if not self.suppress_file_closing:
                self.close()

    def app_iter_range(self, start, stop):
        """Returns an iterator over the data file for range (start, stop)"""
        if start or start == 0:
            self.fp.seek(start)
        if stop is not None:
            length = stop - start
        else:
            length = None
        try:
            for chunk in self:
                if length is not None:
                    length -= len(chunk)
                    if length < 0:
                        # Chop off the extra:
                        yield chunk[:length]
                        break
                yield chunk
        finally:
            if not self.suppress_file_closing:
                self.close()

    def app_iter_ranges(self, ranges, content_type, boundary, size):
        """Returns an iterator over the data file for a set of ranges"""
        if not ranges:
            yield ''
        else:
            try:
                self.suppress_file_closing = True
                for chunk in multi_range_iterator(
                        ranges, content_type, boundary, size,
                        self.app_iter_range):
                    yield chunk
            finally:
                self.suppress_file_closing = False
                try:
                    self.close()
                except DiskFileQuarantined:
                    pass

    def _drop_cache(self, fd, offset, length):
        """Method for no-oping buffer cache drop method."""
        if not self.keep_cache:
            drop_buffer_cache(fd, offset, length)

    def _quarantine(self, msg):
        self.quarantined_dir = self.threadpool.run_in_thread(
            quarantine_renamer, self.device_path, self.data_file)
        self.logger.increment('quarantines')
        self.was_quarantined = msg

    def _handle_close_quarantine(self):
        """Check if file needs to be quarantined"""
        if self.bytes_read != self._obj_size:
            self._quarantine(
                "Bytes read: %s, does not match metadata: %s" % (
                    self.bytes_read, self._obj_size))
        elif self.iter_etag and \
                self.etag != self.iter_etag.hexdigest():
            self._quarantine(
                "ETag %s and file's md5 %s do not match" % (
                    self.etag, self.iter_etag.hexdigest()))

    def close(self, verify_file=True):
        """
        Close the file. Will handle quarantining file if necessary.

        :param verify_file: Defaults to True. If false, will not check
                            file to see if it needs quarantining.
        """
        if self.fp:
            try:
                if verify_file and self.started_at_0 and self.read_to_eof:
                    self._handle_close_quarantine()
            except (Exception, Timeout) as e:
                self.logger.error(_(
                    'ERROR DiskFile %(data_file)s'
                    ' close failure: %(exc)s : %(stack)s'),
                    {'exc': e, 'stack': ''.join(traceback.format_stack()),
                     'data_file': self.data_file})
            finally:
                fp, self.fp = self.fp, None
                fp.close()


class DiskFile(object):
    """
    Manage object files on disk.

    :param mgr: DiskFileManager
    :param device_path: path to the target device or drive
    :param threadpool: thread pool to use for blocking operations
    :param partition: partition on the device in which the object lives
    :param account: account name for the object
    :param container: container name for the object
    :param obj: object name for the object
    :param iter_hook: called when __iter__ returns a chunk
    :param keep_cache: caller's preference for keeping data read in the cache
    """

    def __init__(self, mgr, device_path, threadpool, partition,
                 account, container, obj, iter_hook=None, keep_cache=False):
        self.mgr = mgr
        self.device_path = device_path
        self.threadpool = threadpool or ThreadPool(nthreads=0)
        self.logger = mgr.logger
        self.disk_chunk_size = mgr.disk_chunk_size
        self.bytes_per_sync = mgr.bytes_per_sync
        self.iter_hook = iter_hook
        self.keep_cache = keep_cache
        self.name = '/' + '/'.join((account, container, obj))
        name_hash = hash_path(account, container, obj)
        self.datadir = join(
            device_path, storage_directory(DATADIR, partition, name_hash))
        self.tmpdir = join(device_path, 'tmp')
        self._metadata = None
        self.data_file = None
        self._data_file_size = None
        self.fp = None
        self.iter_etag = None
        self.started_at_0 = False
        self.read_to_eof = False
        self.quarantined_dir = None

    def open(self):
        """
        Open the file and read the metadata.

        This method must populate the _metadata attribute.
        :raises DiskFileCollision: on name mis-match with metadata
        :raises DiskFileDeleted: if it does not exist, or a tombstone is
                                 present
        :raises DiskFileQuarantined: if while reading metadata of the file
                                     some data did pass cross checks
        """
        data_file, meta_file, ts_file = self._get_ondisk_file()
        if not data_file:
            raise self._construct_exception_from_ts_file(ts_file)
        self.fp = self._construct_from_data_file(
            data_file, meta_file)
        self._metadata = self._metadata or {}
        self.data_file = data_file
        return self

    def __enter__(self):
        if self._metadata is None:
            raise DiskFileNotOpen()
        return self

    def __exit__(self, t, v, tb):
        if self.fp is not None:
            fp, self.fp = self.fp, None
            fp.close()

    def _quarantine(self, data_file, msg):
        self.quarantined_dir = self.threadpool.run_in_thread(
            quarantine_renamer, self.device_path, data_file)
        self.logger.increment('quarantines')
        raise DiskFileQuarantined(msg)

    def _get_ondisk_file(self):
        """
        Do the work to figure out if the data directory exists, and if so,
        determine the on-disk files to use.

        :returns: a tuple of data, meta and ts (tombstone) files, in one of
                  three states:

                  1. all three are None

                     data directory does not exist, or there are no files in
                     that directory

                  2. ts_file is not None, data_file is None, meta_file is None

                     object is considered deleted

                  3. data_file is not None, ts_file is None

                     object exists, and optionally has fast-POST metadata
        """
        data_file = meta_file = ts_file = None
        try:
            files = sorted(os.listdir(self.datadir), reverse=True)
        except OSError as err:
            if err.errno != errno.ENOENT:
                raise DiskFileError()
            # The data directory does not exist, so the object cannot exist.
        else:
            for afile in files:
                assert ts_file is None, "On-disk file search loop" \
                    " continuing after tombstone, %s, encountered" % ts_file
                assert data_file is None, "On-disk file search loop" \
                    " continuing after data file, %s, encountered" % data_file
                if afile.endswith('.ts'):
                    meta_file = None
                    ts_file = join(self.datadir, afile)
                    break
                if afile.endswith('.meta') and not meta_file:
                    meta_file = join(self.datadir, afile)
                    # NOTE: this does not exit this loop, since a fast-POST
                    # operation just updates metadata, writing one or more
                    # .meta files, the data file will have an older timestamp,
                    # so we keep looking.
                    continue
                if afile.endswith('.data'):
                    data_file = join(self.datadir, afile)
                    break
        assert ((data_file is None and meta_file is None and ts_file is None)
                or (ts_file is not None and data_file is None
                    and meta_file is None)
                or (data_file is not None and ts_file is None)), \
            "On-disk file search algorithm contract is broken: data_file:" \
            " %s, meta_file: %s, ts_file: %s" % (data_file, meta_file, ts_file)
        return data_file, meta_file, ts_file

    def _construct_exception_from_ts_file(self, ts_file):
        """
        If a tombstone is present it means the object is considered
        deleted. We just need to pull the metadata from the tombstone file
        which has the timestamp to construct the deleted exception. If there
        was no tombstone, just report it does not exist.

        :returns: DiskFileDeleted if the ts_file was provided, else
                  DiskFileNotExist
        """
        if not ts_file:
            exc = DiskFileNotExist()
        else:
            with open(ts_file) as fp:
                metadata = read_metadata(fp)
            # All well and good that we have found a tombstone file, but
            # we don't have a data file so we are just going to raise an
            # exception that we could not find the object, providing the
            # tombstone's timestamp.
            exc = DiskFileDeleted()
            exc.timestamp = metadata['X-Timestamp']
        return exc

    def _verify_data_file(self, data_file, fp):
        """
        Verify the metadata's name value matches what we think the object is
        named.

        :raises DiskFileCollision: if the metadata stored name does not match
                                   the referenced name of the file
        :raises DiskFileNotExist: if the object has expired
        :raises DiskFileQuarantined: if data inconsistencies were detected
                                     between the metadata and the file-system
                                     metadata
        """
        try:
            mname = self._metadata['name']
        except KeyError:
            self._quarantine(data_file, "missing name metadata")
        else:
            if mname != self.name:
                self.logger.error(_('Client path %(client)s does not match '
                                    'path stored in object metadata %(meta)s'),
                                  {'client': self.name, 'meta': mname})
                raise DiskFileCollision('Client path does not match path '
                                        'stored in object metadata')
        try:
            x_delete_at = int(self._metadata['X-Delete-At'])
        except KeyError:
            pass
        except ValueError:
            # Quarantine, the x-delete-at key is present but not an
            # integer.
            self._quarantine(
                data_file, "bad metadata x-delete-at value %s" % (
                    self._metadata['X-Delete-At']))
        else:
            if x_delete_at <= time.time():
                raise DiskFileNotExist('Expired')
        try:
            metadata_size = int(self._metadata['Content-Length'])
        except KeyError:
            self._quarantine(
                data_file, "missing content-length in metadata")
        except ValueError:
            # Quarantine, the content-length key is present but not an
            # integer.
            self._quarantine(
                data_file, "bad metadata content-length value %s" % (
                    self._metadata['Content-Length']))
        fd = fp.fileno()
        try:
            statbuf = os.fstat(fd)
        except OSError as err:
            # Quarantine, we can't successfully stat the file.
            self._quarantine(data_file, "not stat-able: %s" % err)
        else:
            obj_size = statbuf.st_size
        if metadata_size is not None and obj_size != metadata_size:
            self._quarantine(
                data_file, "metadata content-length %s does"
                " not match actual object size %s" % (
                    metadata_size, statbuf.st_size))
        return obj_size

    def _construct_from_data_file(self, data_file, meta_file):
        """
        Open the data file to fetch its metadata, and fetch the metadata from
        the fast-POST .meta file as well if it exists, merging them properly.

        :returns: a tuple of the opened data file pointer, the on-disk size of
                  the object and the object's metadata
        """
        fp = open(data_file, 'rb')
        datafile_metadata = read_metadata(fp)
        if meta_file:
            with open(meta_file) as mfp:
                self._metadata = read_metadata(mfp)
            sys_metadata = dict(
                [(key, val) for key, val in datafile_metadata.iteritems()
                 if key.lower() in DATAFILE_SYSTEM_META])
            self._metadata.update(sys_metadata)
        else:
            self._metadata = datafile_metadata
        self._verify_data_file(data_file, fp)
        return fp

    def get_metadata(self):
        """
        Provide the metadata for an object as a dictionary.

        :returns: object's metadata dictionary
        """
        if self._metadata is None:
            raise DiskFileNotOpen()
        return self._metadata

    def read_metadata(self):
        """
        Return the metadata for an object.

        :returns: metadata dictionary for an object
        """
        with self.open():
            return self.get_metadata()

    def reader(self, iter_hook=None, keep_cache=False):
        """
        Return a swift.common.swob.Response class compatible "app_iter"
        object. The responsibility of closing the open file is passed to the
        DiskFileReader object.

        :param iter_hook:
        :param keep_cache:
        """
        dr = DiskFileReader(self.fp,
                            int(self._metadata['Content-Length']),
                            self._metadata['ETag'],
                            self.data_file, self.threadpool,
                            self.disk_chunk_size,
                            self.mgr.keep_cache_size,
                            self.device_path,
                            self.logger, iter_hook=iter_hook,
                            keep_cache=keep_cache)
        # At this point the reader object is now responsible for closing
        # the file pointer.
        self.fp = None
        return dr

    @contextmanager
    def create(self, size=None):
        """
        Context manager to create a file. We create a temporary file first, and
        then return a DiskFileWriter object to encapsulate the state.

        :param size: optional initial size of file to explicitly allocate on
                     disk
        :raises DiskFileNoSpace: if a size is specified and allocation fails
        """
        if not exists(self.tmpdir):
            mkdirs(self.tmpdir)
        fd, tmppath = mkstemp(dir=self.tmpdir)
        try:
            if size is not None and size > 0:
                try:
                    fallocate(fd, size)
                except OSError:
                    raise DiskFileNoSpace()
            yield DiskFileWriter(self.name, self.datadir, fd, tmppath,
                                 self.bytes_per_sync, self.threadpool)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmppath)
            except OSError:
                pass

    def write_metadata(self, metadata):
        """
        Write a block of metadata to an object.
        """
        with self.create() as writer:
            writer._extension = '.meta'
            writer.put(metadata)

    def delete(self, timestamp):
        """
        Perform a delete for the given object in the given container under the
        given account.

        This creates a tombstone file with the given timestamp, and removes
        any older versions of the object file.  Any file that has an older
        timestamp than timestamp will be deleted.

        :param timestamp: timestamp to compare with each file
        """
        timestamp = normalize_timestamp(timestamp)

        with self.create() as deleter:
            deleter._extension = '.ts'
            deleter.put({'X-Timestamp': timestamp})
