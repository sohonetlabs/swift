# Copyright (c) 2010-2013 OpenStack Foundation
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
Miscellaneous utility functions for use in generating responses.

Why not swift.common.utils, you ask? Because this way we can import things
from swob in here without creating circular imports.
"""

import hashlib
import itertools
import six
import sys
import time

from six.moves.urllib.parse import unquote

from swift.common.constraints import FORMAT2CONTENT_TYPE
from swift.common.exceptions import ListingIterError, SegmentError
from swift.common.header_key_dict import HeaderKeyDict
from swift.common.http import is_success
from swift.common.storage_policy import POLICIES
from swift.common.swob import (
    HTTPBadRequest, HTTPNotAcceptable, HTTPServiceUnavailable, Range,
    is_chunked, multi_range_iterator
)
from swift.common.utils import (
    split_path, validate_device_partition, close_if_possible,
    maybe_multipart_byteranges_to_document_iters,
    multipart_byteranges_to_document_iters, parse_content_type,
    parse_content_range, csv_append, list_from_csv, Spliterator
)
from swift.common.wsgi import make_subrequest

from swift import gettext_ as _


OBJECT_TRANSIENT_SYSMETA_PREFIX = 'x-object-transient-sysmeta-'


def get_param(req, name, default=None):
    """
    Get parameters from an HTTP request ensuring proper handling UTF-8
    encoding.

    :param req: request object
    :param name: parameter name
    :param default: result to return if the parameter is not found
    :returns: HTTP request parameter value
              (as UTF-8 encoded str, not unicode object)
    :raises HTTPBadRequest: if param not valid UTF-8 byte sequence
    """
    value = req.params.get(name, default)
    if value and not isinstance(value, six.text_type):
        try:
            value.decode('utf8')    # Ensure UTF8ness
        except UnicodeDecodeError:
            raise HTTPBadRequest(
                request=req, content_type='text/plain',
                body='"%s" parameter not valid UTF-8' % name)
    return value


def get_listing_content_type(req):
    """
    Determine the content type to use for an account or container listing
    response.

    :param req: request object
    :returns: content type as a string (e.g. text/plain, application/json)
    :raises HTTPNotAcceptable: if the requested content type is not acceptable
    :raises HTTPBadRequest: if the 'format' query param is provided and
             not valid UTF-8
    """
    query_format = get_param(req, 'format')
    if query_format:
        req.accept = FORMAT2CONTENT_TYPE.get(
            query_format.lower(), FORMAT2CONTENT_TYPE['plain'])
    out_content_type = req.accept.best_match(
        ['text/plain', 'application/json', 'application/xml', 'text/xml'])
    if not out_content_type:
        raise HTTPNotAcceptable(request=req)
    return out_content_type


def get_name_and_placement(request, minsegs=1, maxsegs=None,
                           rest_with_last=False):
    """
    Utility function to split and validate the request path and storage
    policy.  The storage policy index is extracted from the headers of
    the request and converted to a StoragePolicy instance.  The
    remaining args are passed through to
    :meth:`split_and_validate_path`.

    :returns: a list, result of :meth:`split_and_validate_path` with
              the BaseStoragePolicy instance appended on the end
    :raises HTTPServiceUnavailable: if the path is invalid or no policy exists
             with the extracted policy_index.
    """
    policy_index = request.headers.get('X-Backend-Storage-Policy-Index')
    policy = POLICIES.get_by_index(policy_index)
    if not policy:
        raise HTTPServiceUnavailable(
            body=_("No policy with index %s") % policy_index,
            request=request, content_type='text/plain')
    results = split_and_validate_path(request, minsegs=minsegs,
                                      maxsegs=maxsegs,
                                      rest_with_last=rest_with_last)
    results.append(policy)
    return results


def split_and_validate_path(request, minsegs=1, maxsegs=None,
                            rest_with_last=False):
    """
    Utility function to split and validate the request path.

    :returns: result of :meth:`~swift.common.utils.split_path` if
              everything's okay
    :raises HTTPBadRequest: if something's not okay
    """
    try:
        segs = split_path(unquote(request.path),
                          minsegs, maxsegs, rest_with_last)
        validate_device_partition(segs[0], segs[1])
        return segs
    except ValueError as err:
        raise HTTPBadRequest(body=str(err), request=request,
                             content_type='text/plain')


def is_user_meta(server_type, key):
    """
    Tests if a header key starts with and is longer than the user
    metadata prefix for given server type.

    :param server_type: type of backend server i.e. [account|container|object]
    :param key: header key
    :returns: True if the key satisfies the test, False otherwise
    """
    if len(key) <= 8 + len(server_type):
        return False
    return key.lower().startswith(get_user_meta_prefix(server_type))


def is_sys_meta(server_type, key):
    """
    Tests if a header key starts with and is longer than the system
    metadata prefix for given server type.

    :param server_type: type of backend server i.e. [account|container|object]
    :param key: header key
    :returns: True if the key satisfies the test, False otherwise
    """
    if len(key) <= 11 + len(server_type):
        return False
    return key.lower().startswith(get_sys_meta_prefix(server_type))


def is_sys_or_user_meta(server_type, key):
    """
    Tests if a header key starts with and is longer than the user or system
    metadata prefix for given server type.

    :param server_type: type of backend server i.e. [account|container|object]
    :param key: header key
    :returns: True if the key satisfies the test, False otherwise
    """
    return is_user_meta(server_type, key) or is_sys_meta(server_type, key)


def is_object_transient_sysmeta(key):
    """
    Tests if a header key starts with and is longer than the prefix for object
    transient system metadata.

    :param key: header key
    :returns: True if the key satisfies the test, False otherwise
    """
    if len(key) <= len(OBJECT_TRANSIENT_SYSMETA_PREFIX):
        return False
    return key.lower().startswith(OBJECT_TRANSIENT_SYSMETA_PREFIX)


def strip_user_meta_prefix(server_type, key):
    """
    Removes the user metadata prefix for a given server type from the start
    of a header key.

    :param server_type: type of backend server i.e. [account|container|object]
    :param key: header key
    :returns: stripped header key
    """
    return key[len(get_user_meta_prefix(server_type)):]


def strip_sys_meta_prefix(server_type, key):
    """
    Removes the system metadata prefix for a given server type from the start
    of a header key.

    :param server_type: type of backend server i.e. [account|container|object]
    :param key: header key
    :returns: stripped header key
    """
    return key[len(get_sys_meta_prefix(server_type)):]


def strip_object_transient_sysmeta_prefix(key):
    """
    Removes the object transient system metadata prefix from the start of a
    header key.

    :param key: header key
    :returns: stripped header key
    """
    return key[len(OBJECT_TRANSIENT_SYSMETA_PREFIX):]


def get_user_meta_prefix(server_type):
    """
    Returns the prefix for user metadata headers for given server type.

    This prefix defines the namespace for headers that will be persisted
    by backend servers.

    :param server_type: type of backend server i.e. [account|container|object]
    :returns: prefix string for server type's user metadata headers
    """
    return 'x-%s-%s-' % (server_type.lower(), 'meta')


def get_sys_meta_prefix(server_type):
    """
    Returns the prefix for system metadata headers for given server type.

    This prefix defines the namespace for headers that will be persisted
    by backend servers.

    :param server_type: type of backend server i.e. [account|container|object]
    :returns: prefix string for server type's system metadata headers
    """
    return 'x-%s-%s-' % (server_type.lower(), 'sysmeta')


def get_object_transient_sysmeta(key):
    """
    Returns the Object Transient System Metadata header for key.
    The Object Transient System Metadata namespace will be persisted by
    backend object servers. These headers are treated in the same way as
    object user metadata i.e. all headers in this namespace will be
    replaced on every POST request.

    :param key: metadata key
    :returns: the entire object transient system metadata header for key
    """
    return '%s%s' % (OBJECT_TRANSIENT_SYSMETA_PREFIX, key)


def remove_items(headers, condition):
    """
    Removes items from a dict whose keys satisfy
    the given condition.

    :param headers: a dict of headers
    :param condition: a function that will be passed the header key as a
                      single argument and should return True if the header
                      is to be removed.
    :returns: a dict, possibly empty, of headers that have been removed
    """
    removed = {}
    keys = filter(condition, headers)
    removed.update((key, headers.pop(key)) for key in keys)
    return removed


def copy_header_subset(from_r, to_r, condition):
    """
    Will copy desired subset of headers from from_r to to_r.

    :param from_r: a swob Request or Response
    :param to_r: a swob Request or Response
    :param condition: a function that will be passed the header key as a
                      single argument and should return True if the header
                      is to be copied.
    """
    for k, v in from_r.headers.items():
        if condition(k):
            to_r.headers[k] = v


class SegmentedIterable(object):
    """
    Iterable that returns the object contents for a large object.

    :param req: original request object
    :param app: WSGI application from which segments will come

    :param listing_iter: iterable yielding dicts describing the object
        segments to fetch, and containing the following keys: ['path',
        'hash', 'bytes', 'first-byte', 'last-byte', 'preamble', 'postamble']

        If seg_dict['hash'] is None, no MD5 verification will be done.

        If seg_dict['bytes'] is None, no length verification will be done.

        If seg_dict['first-byte'] and seg_dict['last-byte'] are None, then
        the entire object will be fetched.

        if seg_dict['preamble'] or seg_dict['postamble'] are not None, then
        the object will be prefixed by the preamble data, and suffixed by the
        postamble data.

    :param max_get_time: maximum permitted duration of a GET request (seconds)
    :param logger: logger object
    :param swift_source: value of swift.source in subrequest environ
                         (just for logging)
    :param ua_suffix: string to append to user-agent.
    :param name: name of manifest (used in logging only)
    :param response_body_length: optional response body length for
                                 the response being sent to the client.
    """

    def __init__(self, req, app, listing_iter, max_get_time,
                 logger, ua_suffix, swift_source,
                 name='<not specified>', response_body_length=None):
        self.req = req
        self.app = app
        self.listing_iter = listing_iter
        self.max_get_time = max_get_time
        self.logger = logger
        self.ua_suffix = " " + ua_suffix
        self.swift_source = swift_source
        self.name = name
        self.response_body_length = response_body_length
        self.peeked_chunk = None
        self.app_iter = self._internal_iter()
        self.validated_first_segment = False
        self.current_resp = None

    def _coalescing_iter(self):
        """
        The _coalescing_iter is responsible for combining sequential range
        requests into the same object into a single request where possible.
        Note that coalescing requests to the same object may not be possible
        depending on the presence of pre/post amble data, or when the number
        of ranges would cause the request to fail
        """
        pending_req = None
        pending_dict = None

        try:
            for seg_dict in self.listing_iter:
                seg_path = seg_dict['path']
                seg_size = seg_dict.get('bytes')
                if seg_size is not None:
                    seg_size = int(seg_size)
                first_byte = seg_dict.get('first_byte') or 0
                last_byte = seg_dict.get('last_byte')
                seg_preamble = seg_dict.get('preamble')
                seg_postamble = seg_dict.get('postamble')

                # The "multipart-manifest=get" query param ensures that the
                # segment is a plain old object, not some flavor of large
                # object; therefore, its etag is its MD5sum and hence we can
                # check it.
                path = seg_path + '?multipart-manifest=get'
                seg_req = make_subrequest(
                    self.req.environ, path=path, method='GET',
                    headers={
                        'x-auth-token': self.req.headers.get('x-auth-token')
                    },
                    agent=('%(orig)s ' + self.ua_suffix),
                    swift_source=self.swift_source
                )

                # Only add a range here if we can potentially coalesce the
                # requests. Otherwise, let the pre_post_amble_iter handle it
                # later and let it deal with calculating the ranges within the
                # segment after the preamble and postamble sizes are factored
                # in.
                if not seg_preamble and not seg_postamble:
                    go_to_end = (
                        last_byte is None or
                        (seg_size is not None and last_byte == seg_size - 1)
                    )
                    seg_req_rangeval = None
                    if first_byte != 0 or not go_to_end:
                        seg_req_rangeval = "%s-%s" % (
                            first_byte, '' if go_to_end else last_byte
                        )
                        seg_req.headers['Range'] = "bytes=" + seg_req_rangeval

                # We can only coalesce if
                #  - there is no segment preamble
                #  - there is no segment postamble
                #  - we have a previous request and the paths match
                #  - we know the segment size (so we can validate the ranges)
                can_coalesce = (
                    not seg_preamble and
                    not seg_postamble and
                    (pending_req and pending_req.path == seg_req.path) and
                    seg_size is not None
                )
                if can_coalesce:
                    # Make a new Range object so that we don't goof up the
                    # existing one in case of invalid ranges. Note that a
                    # range set with too many individual byteranges is
                    # invalid, so we can combine N valid byteranges and 1
                    # valid byterange and get an invalid range set.
                    if pending_req.range:
                        new_range_str = str(pending_req.range)
                    else:
                        new_range_str = "bytes=0-%d" % (seg_size - 1)

                    if seg_req.range:
                        new_range_str += "," + seg_req_rangeval
                    else:
                        new_range_str += ",0-%d" % (seg_size - 1)

                    # Try to make a range object with the extended range
                    if Range(new_range_str).ranges_for_length(seg_size):
                        # Good news! We can coalesce the requests
                        pending_req.headers['Range'] = new_range_str
                        continue
                    # else, Too many ranges, or too much backtracking, or ...

                if pending_req:
                    yield pending_req, pending_dict

                pending_req = seg_req
                pending_dict = seg_dict

        except ListingIterError:
            e_type, e_value, e_traceback = sys.exc_info()
            if pending_req:
                yield pending_req, seg_dict
            six.reraise(e_type, e_value, e_traceback)

        if pending_req:
            yield pending_req, pending_dict

    def _pre_post_amble_iter(self):
        """
        The _pre_post_amble_iter is responsible for yielding data from segment
        preambles, segment objects, and from segment postambles. Given a
        first_byte and last_byte in each segment dict, the _pre_post_amble_iter
        yields the appropriate range within preamble + segment_data + postamble

        The _pre_post_amble_iter wraps the _coalescing_iter so that segment
        requests are combined where possible
        """
        bytes_left = self.response_body_length

        for seg_req, seg_dict in self._coalescing_iter():
            seg_path = seg_dict['path']
            seg_etag = seg_dict.get('hash')
            seg_size = seg_dict.get('bytes')
            if seg_size is not None:
                seg_size = int(seg_size)
            first_byte = seg_dict.get('first_byte') or 0
            last_byte = seg_dict.get('last_byte')
            preamble = seg_dict.get('preamble', b'')
            preamble_size = len(preamble)
            postamble = seg_dict.get('postamble', b'')
            postamble_size = len(postamble)

            # Handle any bytes required from the tar header
            if first_byte < preamble_size:
                first_preamble_byte = first_byte
                if last_byte is None:
                    last_preamble_byte = preamble_size
                else:
                    last_preamble_byte = min(last_byte + 1, preamble_size)
                if (last_preamble_byte - first_preamble_byte) > 0:
                    preamble_data = preamble[
                        first_preamble_byte:last_preamble_byte
                    ]
                    if bytes_left is not None:
                        bytes_left -= len(preamble_data)
                    yield preamble_data

            # Break the loop if we already have everything we need
            if last_byte is not None and last_byte < preamble_size:
                continue

            if bytes_left is not None and bytes_left <= 0:
                continue

            # Handle bytes required from the object itself.
            # If we've already coalesced this request, then we know
            # that no pre/postamble handling is required and the range
            # header has already been dealt with.
            go_to_end = (
                last_byte is None or
                (seg_size is not None and last_byte == seg_size - 1)
            )
            handle_segment_range = (
                seg_req.headers.get('Range') is None and
                not go_to_end
            )
            first_seg_byte = None
            if handle_segment_range:
                first_seg_byte = max(0, first_byte - preamble_size)
                last_seg_byte = None
                if last_byte is not None:
                    last_seg_byte = max(0, last_byte - preamble_size)
                if seg_size is not None and last_seg_byte is not None:
                    last_seg_byte = min(last_seg_byte, seg_size - 1)

                # We really need to exit here or risk making requests
                # for segment data that return 416. When dealing with
                # pre/postambles and range requests we just have to know
                # the size of the segment.
                cannot_make_range_request = (
                    seg_size is None and
                    first_seg_byte and
                    (preamble or postamble)
                )
                if cannot_make_range_request:
                    raise SegmentError(
                        'ERROR: While processing manifest %s, '
                        'Cannot omit segment size when specifying preamble '
                        'or postamble' % self.name
                    )

                add_range = first_seg_byte > 0 or last_seg_byte is not None
                if add_range:
                    if last_seg_byte is None:
                        last_seg_byte = ''
                    else:
                        last_seg_byte_is_end = (
                            seg_size is not None and
                            last_seg_byte == seg_size - 1
                        )
                        if last_seg_byte_is_end:
                            last_seg_byte = ''

                    seg_range_val = "%s-%s" % (first_seg_byte, last_seg_byte)
                    seg_req.headers['Range'] = "bytes=%s" % seg_range_val

            # Don't make unnecessary requests that we never read from.
            # Unspecified segment size means we have to try anyway.
            # If the segment size is given we can decide whether to perform
            # the request by making sure that the requested range lies within
            # the segment body
            segment_bytes_served = 0
            segment_request_required = (
                seg_size is None or
                (
                    (
                        first_seg_byte is not None and
                        first_seg_byte < seg_size
                    ) or
                    (
                        first_byte < preamble_size + seg_size and
                        (
                            last_byte is None or
                            last_byte >= preamble_size
                        )
                    )
                )
            )
            if segment_request_required:
                seg_resp = seg_req.get_response(self.app)
                self.current_resp = seg_resp

                if not is_success(seg_resp.status_int):
                    close_if_possible(seg_resp.app_iter)
                    raise SegmentError(
                        'ERROR: While processing manifest %s, '
                        'got %d while retrieving %s' %
                        (
                            self.name,
                            seg_resp.status_int,
                            seg_path
                        )
                    )

                # The content-length check is for security reasons. It
                # seems possible that an attacker could upload a >1MiB
                # object and then replace it with a much smaller object
                # with the same etag. They could then create a big
                # nested SLO that calls that object many times which
                # would hammer the object servers.
                # If this is a range request, don't check content-length
                # because it won't match.
                segment_invalid = (
                    (
                        seg_etag is not None and
                        (seg_resp.etag != seg_etag)
                    ) or
                    (
                        seg_size is not None and
                        (seg_resp.content_length != seg_size) and
                        seg_req.headers.get('Range') is None
                    )
                )
                if segment_invalid:
                    close_if_possible(seg_resp.app_iter)
                    raise SegmentError(
                        'Sub-Object no longer valid: '
                        '%(name)s etag: %(r_etag)s != %(s_etag)s or '
                        '%(r_size)s != %(s_size)s.' %
                        {
                            'name': seg_req.path,
                            'r_etag': seg_resp.etag,
                            'r_size': seg_resp.content_length,
                            's_etag': seg_etag,
                            's_size': seg_size
                        }
                    )

                seg_hash = None
                if seg_resp.etag and not seg_req.headers.get('Range'):
                    # Only calculate the MD5 if we can use it to validate
                    seg_hash = hashlib.md5()

                doc_iters = maybe_multipart_byteranges_to_document_iters(
                    seg_resp.app_iter,
                    seg_resp.headers['Content-Type'])

                for chunk in itertools.chain.from_iterable(doc_iters):
                    if seg_hash:
                        seg_hash.update(chunk)
                    if bytes_left is None:
                        segment_bytes_served += len(chunk)
                        yield chunk
                    elif bytes_left >= len(chunk):
                        yield chunk
                        segment_bytes_served += len(chunk)
                        bytes_left -= len(chunk)
                    else:
                        yield chunk[:bytes_left]
                        segment_bytes_served += len(chunk[:bytes_left])
                        bytes_left -= len(chunk)
                        raise SegmentError(
                            'Too many bytes for %(name)s; truncating in '
                            '%(seg)s with %(left)d bytes left' %
                            {
                                'name': self.name, 'seg': seg_req.path,
                                'left': bytes_left
                            }
                        )

                close_if_possible(seg_resp.app_iter)

                # Validate the data we received against the response headers
                if seg_resp is not None:
                    etag_invalid = (
                        seg_resp.etag and
                        (
                            # Only check the etag when no range is given
                            seg_hash and
                            (seg_hash.hexdigest() != seg_resp.etag)
                        )
                    )
                    if etag_invalid:
                        raise SegmentError(
                            "Bad MD5 checksum in %(name)s for %(obj)s: "
                            "headers had %(etag)s, but object MD5 was "
                            "actually %(actual)s" %
                            {
                                'obj': seg_req.path,
                                'etag': seg_resp.etag,
                                'name': self.name,
                                'actual': seg_hash.hexdigest()
                            }
                        )

                    size_invalid = (
                        first_seg_byte == 0 and
                        last_seg_byte == '' and
                        seg_resp.content_length and
                        segment_bytes_served != seg_resp.content_length
                    )
                    if size_invalid:
                        raise SegmentError(
                            "Incorrect number of bytes received for %(name)s "
                            "in %(obj)s: content_length header was %(length)s"
                            ", but byte count received was actually %(actual)s"
                            % {
                                'obj': seg_req.path,
                                'length': seg_resp.content_length,
                                'name': self.name,
                                'actual': segment_bytes_served
                            }
                        )

            # Break the loop if we already have everything we need.
            all_bytes_served = (
                postamble_size == 0 or
                (
                    last_byte is not None and
                    last_byte < preamble_size + (
                        seg_size or segment_bytes_served
                    )
                )
            )
            if all_bytes_served:
                continue

            # Handle any bytes required from the postamble.
            # If we're here, then an earlier check guarantees
            # that seg_size is not None
            first_postamble_byte = max(
                0, first_byte - (preamble_size + seg_size)
            )
            num_postamble_bytes = last_byte - (
                preamble_size + seg_size
            ) + 1
            if num_postamble_bytes > postamble_size:
                raise SegmentError(
                    'Not enough bytes (%s > %s) in postamble for %s; '
                    'closing connection' %
                    (num_postamble_bytes, postamble_size, self.name)
                )
            # Because we didn't 'continue' before testing the postamble
            # we know we are serving at least one byte here
            postamble_data = postamble[
                first_postamble_byte:num_postamble_bytes
            ]
            yield postamble_data
            if bytes_left is not None:
                bytes_left -= len(postamble_data)

        if bytes_left:  # Error if bytes_left is not None and non-zero
            raise SegmentError(
                'Not enough bytes for %s; closing connection' % self.name
            )

    def _time_limit_iter(self):
        """
        The _time_limit_iter wraps the _pre_post_amble_iter and simply ensures
        that a request does not exceed the time limit for a single request.
        """
        start_time = time.time()

        def _check_time_exceeded():
            if time.time() - start_time > self.max_get_time:
                raise SegmentError(
                    'ERROR: While processing manifest %s, '
                    'max LO GET time of %ds exceeded' %
                    (self.name, self.max_get_time)
                )
        try:
            for res in self._pre_post_amble_iter():
                yield res
                _check_time_exceeded()
        except ListingIterError:
            e_type, e_value, e_traceback = sys.exc_info()
            _check_time_exceeded()
            six.reraise(e_type, e_value, e_traceback)

    def _internal_iter(self):
        """
        The _internal_iter is the top level iterator within SegmentedIterable.
        Its only responsibility is to yield results from the _time_limit_iter,
        log exceptions and attempt to close the response iterator.
        """
        try:
            for chunk in self._time_limit_iter():
                yield chunk
        except (ListingIterError, SegmentError):
            self.logger.exception(_('ERROR: An error occurred '
                                    'while retrieving segments'))
            raise
        finally:
            if self.current_resp:
                close_if_possible(self.current_resp.app_iter)

    def app_iter_range(self, *a, **kw):
        """
        swob.Response will only respond with a 206 status in certain cases; one
        of those is if the body iterator responds to .app_iter_range().

        However, this object (or really, its listing iter) is smart enough to
        handle the range stuff internally, so we just no-op this out for swob.
        """
        return self

    def app_iter_ranges(self, ranges, content_type, boundary, content_size):
        """
        This method assumes that iter(self) yields all the data bytes that
        go into the response, but none of the MIME stuff. For example, if
        the response will contain three MIME docs with data "abcd", "efgh",
        and "ijkl", then iter(self) will give out the bytes "abcdefghijkl".

        This method inserts the MIME stuff around the data bytes.
        """
        si = Spliterator(self)
        mri = multi_range_iterator(
            ranges, content_type, boundary, content_size,
            lambda start, end_plus_one: si.take(end_plus_one - start))
        try:
            for x in mri:
                yield x
        finally:
            self.close()

    def validate_first_segment(self):
        """
        Start fetching object data to ensure that the first segment (if any) is
        valid. This is to catch cases like "first segment is missing" or
        "first segment's etag doesn't match manifest".

        Note: this does not validate that you have any segments. A
        zero-segment large object is not erroneous; it is just empty.
        """
        if self.validated_first_segment:
            return
        self.validated_first_segment = True

        try:
            self.peeked_chunk = next(self.app_iter)
        except StopIteration:
            pass

    def __iter__(self):
        if self.peeked_chunk is not None:
            pc = self.peeked_chunk
            self.peeked_chunk = None
            return itertools.chain([pc], self.app_iter)
        else:
            return self.app_iter

    def close(self):
        """
        Called when the client disconnect. Ensure that the connection to the
        backend server is closed.
        """
        close_if_possible(self.app_iter)


def http_response_to_document_iters(response, read_chunk_size=4096):
    """
    Takes a successful object-GET HTTP response and turns it into an
    iterator of (first-byte, last-byte, length, headers, body-file)
    5-tuples.

    The response must either be a 200 or a 206; if you feed in a 204 or
    something similar, this probably won't work.

    :param response: HTTP response, like from bufferedhttp.http_connect(),
        not a swob.Response.
    """
    chunked = is_chunked(dict(response.getheaders()))

    if response.status == 200:
        if chunked:
            # Single "range" that's the whole object with an unknown length
            return iter([(0, None, None, response.getheaders(),
                          response)])

        # Single "range" that's the whole object
        content_length = int(response.getheader('Content-Length'))
        return iter([(0, content_length - 1, content_length,
                      response.getheaders(), response)])

    content_type, params_list = parse_content_type(
        response.getheader('Content-Type'))
    if content_type != 'multipart/byteranges':
        # Single range; no MIME framing, just the bytes. The start and end
        # byte indices are in the Content-Range header.
        start, end, length = parse_content_range(
            response.getheader('Content-Range'))
        return iter([(start, end, length, response.getheaders(), response)])
    else:
        # Multiple ranges; the response body is a multipart/byteranges MIME
        # document, and we have to parse it using the MIME boundary
        # extracted from the Content-Type header.
        params = dict(params_list)
        return multipart_byteranges_to_document_iters(
            response, params['boundary'], read_chunk_size)


def update_etag_is_at_header(req, name):
    """
    Helper function to update an X-Backend-Etag-Is-At header whose value is a
    list of alternative header names at which the actual object etag may be
    found. This informs the object server where to look for the actual object
    etag when processing conditional requests.

    Since the proxy server and/or middleware may set alternative etag header
    names, the value of X-Backend-Etag-Is-At is a comma separated list which
    the object server inspects in order until it finds an etag value.

    :param req: a swob Request
    :param name: name of a sysmeta where alternative etag may be found
    """
    if ',' in name:
        # HTTP header names should not have commas but we'll check anyway
        raise ValueError('Header name must not contain commas')
    existing = req.headers.get("X-Backend-Etag-Is-At")
    req.headers["X-Backend-Etag-Is-At"] = csv_append(
        existing, name)


def resolve_etag_is_at_header(req, metadata):
    """
    Helper function to resolve an alternative etag value that may be stored in
    metadata under an alternate name.

    The value of the request's X-Backend-Etag-Is-At header (if it exists) is a
    comma separated list of alternate names in the metadata at which an
    alternate etag value may be found. This list is processed in order until an
    alternate etag is found.

    The left most value in X-Backend-Etag-Is-At will have been set by the left
    most middleware, or if no middleware, by ECObjectController, if an EC
    policy is in use. The left most middleware is assumed to be the authority
    on what the etag value of the object content is.

    The resolver will work from left to right in the list until it finds a
    value that is a name in the given metadata. So the left most wins, IF it
    exists in the metadata.

    By way of example, assume the encrypter middleware is installed. If an
    object is *not* encrypted then the resolver will not find the encrypter
    middleware's alternate etag sysmeta (X-Object-Sysmeta-Crypto-Etag) but will
    then find the EC alternate etag (if EC policy). But if the object *is*
    encrypted then X-Object-Sysmeta-Crypto-Etag is found and used, which is
    correct because it should be preferred over X-Object-Sysmeta-Crypto-Etag.

    :param req: a swob Request
    :param metadata: a dict containing object metadata
    :return: an alternate etag value if any is found, otherwise None
    """
    alternate_etag = None
    metadata = HeaderKeyDict(metadata)
    if "X-Backend-Etag-Is-At" in req.headers:
        names = list_from_csv(req.headers["X-Backend-Etag-Is-At"])
        for name in names:
            if name in metadata:
                alternate_etag = metadata[name]
                break
    return alternate_etag
