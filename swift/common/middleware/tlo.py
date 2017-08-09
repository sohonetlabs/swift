# Copyright (c) 2016 OpenStack Foundation
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
Middleware that will provide Tar Large Object (TLO) support.

This feature builds upon the preamble and postamble support in SLO to
provide the capability for a user to upload a manifest that allows
multiple objects to be downloaded as a tarball.

----------------------
Uploading the Manifest
----------------------

After the user has uploaded the objects to be downloaded, a manifest is
uploaded. The request must be a PUT with the query parameter::

    ?tar-manifest=put

The body of this request will be an ordered list of object descriptions in
JSON format. The data to be supplied for each segment is:

=========== ========================================================
Key         Description
=========== ========================================================
path        the path to the object (not including account)
            /container/object_name
size        the size of the object in bytes
etag        (optional) the ETag given back when the object was PUT
range       (optional) the (inclusive) range within the object to
            use as a file in the tarball. If omitted, the entire
            object is used
name        (optional) the name that should be presented by the
            tarball for the object. If omitted, the object path
            will be used (not including account or leading slash)
mode        (optional) the mode that should be presented by the
            tarball for the object. If omitted, the file mode will
            default to 0o644.
=========== ========================================================

The format of the list will be:

  .. code::

    [
        {
            "path": "/cont/object",
            "etag": "etagoftheobject",
            "size": 10485760,
            "range": "1048576-2097151",
            "name": "object.name",
            "mode": "0644"
        },
        ...
    ]

The number of object segments is limited by the settings for SLO, larger
tarballs can be created with a concatenation request (see below for details).

--------------
Deleting a TLO
--------------

Much like SLO, a DELETE request will just delete the manifest object itself.

A DELETE with a query parameter::

    ?tar-manifest=delete

will delete all the objects referenced in the manifest and then the manifest
itself. The failure response will be similar to the bulk delete middleware.

------------------------
Modifying a Large Object
------------------------

PUTs / POSTs will work as expected, PUTs will just overwrite the manifest
object for example.

------------------
Container Listings
------------------

In a container listing the size listed for TLO manifest objects will be the
total_size of the concatenated segments in the manifest along. The overall
X-Container-Bytes-Used for the container (and subsequently for the account)
will not reflect total_size of the manifest but the actual size of the json
data stored. The reason for this somewhat confusing discrepancy is we want the
container listing to reflect the size of the manifest object when it is
downloaded. We do not, however, want to count the bytes-used twice (for both
the manifest and the segments it's referring to) in the container and account
metadata which can be used for stats purposes.
"""

import base64
import json
import mimetypes
import six
import tarfile
import time


from swift.common.swob import (
    Request, HTTPBadRequest, HTTPRequestEntityTooLarge, HTTPLengthRequired,
    HTTPException
)
from swift.common.utils import get_logger, split_path, register_swift_info
from swift.common.middleware.slo import (
    DEFAULT_MAX_MANIFEST_SEGMENTS, DEFAULT_MAX_MANIFEST_SIZE
)


REQUIRED_TLO_KEYS = set(['path', 'size_bytes'])
OPTIONAL_TLO_KEYS = set([
    'range', 'etag', 'size_bytes', 'name', 'uid', 'gid', 'mode'
])
ALLOWED_TLO_KEYS = REQUIRED_TLO_KEYS | OPTIONAL_TLO_KEYS


def _tar_padding(size):
    """
    Given a size of bytes, create a tar padding to a complete block
    """
    _bs = tarfile.BLOCKSIZE
    return base64.b64encode('\x00' * (_bs - (size - 1) % _bs - 1))


def _tar_header(name, size, mode=0o644):
    """
    Build a tar header for a given file name, size and mode
    """
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.type = tarfile.REGTYPE
    info.mode = mode
    info.mtime = time.time()
    return base64.b64encode(info.tobuf(format=tarfile.GNU_FORMAT))


def parse_and_validate_input(req_body, req_path):
    """
    Given a request body, parses it and returns a list of dictionaries.

    The input structure is described above, and the output structure is
    a valid SLO manifest including preamble and postamble data containing
    encoded tar header and footer data.

    :raises: HTTPException on parse errors or semantic errors (e.g. missing
             JSON keys, bad JSON value types...)

    :returns: a list of dictionaries on success
    """
    slo_data = []
    try:
        parsed_data = json.loads(req_body)
    except ValueError:
        raise HTTPBadRequest("Manifest must be valid JSON.\n")

    if not isinstance(parsed_data, list):
        raise HTTPBadRequest("Manifest must be a list.\n")

    # If we got here, req_path refers to an object, so this won't ever raise
    # ValueError.
    vrs, account, _junk = split_path(req_path, 3, 3, True)

    errors = []
    for seg_index, seg_dict in enumerate(parsed_data):
        if not isinstance(seg_dict, dict):
            errors.append("Index %d: not a JSON object" % seg_index)
            continue

        missing_keys = [k for k in REQUIRED_TLO_KEYS if k not in seg_dict]
        if missing_keys:
            errors.append(
                "Index %d: missing keys %s"
                % (
                    seg_index,
                    ", ".join('"%s"' % (mk,) for mk in sorted(missing_keys))
                )
            )
            continue

        extraneous_keys = [k for k in seg_dict if k not in ALLOWED_TLO_KEYS]
        if extraneous_keys:
            errors.append(
                "Index %d: extraneous keys %s"
                % (
                    seg_index,
                    ", ".join(
                        '"%s"' % (ek,) for ek in sorted(extraneous_keys)
                    )
                )
            )
            continue

        if not isinstance(seg_dict['path'], six.string_types):
            errors.append("Index %d: \"path\" must be a string" % seg_index)
            continue

        # We validate the size here because this is optional in SLO
        seg_size = seg_dict.get('size_bytes')
        if seg_size is None:
            errors.append("Index %d: a valid tar object size is required")
        else:
            try:
                seg_size = int(seg_size)
                seg_dict['size_bytes'] = seg_size
            except (TypeError, ValueError):
                errors.append("Index %d: invalid size_bytes" % seg_index)
                continue

        seg_name = seg_dict.get('name', seg_dict.get['path'])
        if not isinstance(seg_name, six.string_types):
            errors.append(
                "Index %d: invalid tar name specified for object" % seg_index
            )
            continue
        else:
            # Don't allow dangerous tarballs
            seg_name = seg_name.lstrip('/')

        seg_mode = seg_dict.get('mode')
        if seg_mode is None:
            seg_mode = 0o644
        try:
            seg_mode = int(seg_mode, 8)
        except (TypeError, ValueError):
            errors.append("Index %d: invalid mode" % seg_index)
            continue

        seg_data = {
            "path": "/cont/object",
            "size_bytes": seg_size,
        }
        optional_seg_data = {
            k: seg_dict[k] for k in ['range', 'etag'] if k in seg_dict
        }
        seg_data.extend(optional_seg_data)
        slo_data.append(seg_data)

    if errors:
        error_message = "".join(e + "\n" for e in errors)
        raise HTTPBadRequest(
            error_message, headers={"Content-Type": "text/plain"}
        )

    return slo_data


class TarLargeObject(object):
    """
    TarLargeObject Middleware

    See above for a full description.

    The proxy logs created for any subrequests made will have swift.source set
    to "TLO".

    :param app: The next WSGI filter or app in the paste.deploy chain.
    :param conf: The configuration dict for the middleware.
    """

    def __init__(
        self, app, conf, max_manifest_segments=DEFAULT_MAX_MANIFEST_SEGMENTS,
        max_manifest_size=DEFAULT_MAX_MANIFEST_SIZE
    ):
        self.conf = conf
        self.app = app
        self.logger = get_logger(conf, log_route='tlo')
        self.max_manifest_segments = max_manifest_segments
        self.max_manifest_size = max_manifest_size

    @staticmethod
    def _process_seg_dict(seg_dict):
        """
        TODO: Add support for inline sub-tars
        """
        processed = {
            k: seg_dict[k] for k in seg_dict
            if k in ['path', 'etag', 'size', 'range'] and seg_dict[k]
        }
        seg_name = seg_dict['name']
        seg_size = seg_dict['size']
        seg_mode = seg_dict['mode']
        processed.update({
            "preamble": _tar_header(seg_name, seg_size, seg_mode),
            "postamble": _tar_padding(seg_size)
        })

        return processed

    def handle_tar_put(self, req, start_response):
        """
        Will handle the PUT of a TLO manifest.

        Creates the relevant SLO manifest based on the TLO manifest contents
        and passes the request on to the SLO middleware. Uses WSGIContext to
        call self and start_response and returns a WSGI iterator.

        :params req: a swob.Request with an obj in path
        :raises: HttpException on errors
        """
        try:
            vrs, account, container, obj = req.split_path(1, 4, True)
        except ValueError:
            return self.app(req.environ, start_response)

        if (
            req.content_length is None and
            req.headers.get('transfer-encoding', '').lower() != 'chunked'
        ):
            raise HTTPLengthRequired(request=req)

        parsed_data = parse_and_validate_input(
            req.body_file.read(self.max_manifest_size),
            req.path
        )

        if len(parsed_data) > self.max_manifest_segments:
            raise HTTPRequestEntityTooLarge(
                'Number of segments must be <= %d' %
                self.max_manifest_segments
            )

        processed_data = []
        for seg_dict in parsed_data:
            processed_data.append(self._process_seg_dict(seg_dict))

        # TODO: Append 2*tar block padding

        json_data = json.dumps(processed_data)
        if six.PY3:
            json_data = json_data.encode('utf-8')
        req.body = json_data
        req.params.pop('tar-manifest')
        req.params['multipart-manifest'] = 'put'

        env = req.environ
        # TODO: update content type to be tar
        if not env.get('CONTENT_TYPE'):
            guessed_type, _junk = mimetypes.guess_type(req.path_info)
            env['CONTENT_TYPE'] = guessed_type or 'application/octet-stream'

        return self.app(env, start_response)

    def __call__(self, env, start_response):
        """
        WSGI entry point
        """
        if env.get('swift.slo_override'):
            return self.app(env, start_response)

        req = Request(env)
        try:
            vrs, account, container, obj = req.split_path(4, 4, True)
        except ValueError:
            return self.app(env, start_response)

        try:
            if (
                req.method == 'PUT' and
                req.params.get('tar-manifest') == 'put'
            ):
                return self.handle_tar_put(req, start_response)
            if 'X-Tar-Large-Object' in req.headers:
                raise HTTPBadRequest(
                    request=req,
                    body='X-Tar-Large-Object is a reserved header. '
                    'To create a tar large object add query param '
                    'tar-manifest=put.')
        except HTTPException as err_resp:
            return err_resp(env, start_response)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    max_manifest_segments = int(conf.get(
        'max_manifest_segments', DEFAULT_MAX_MANIFEST_SEGMENTS
    ))
    max_manifest_size = int(conf.get(
        'max_manifest_size', DEFAULT_MAX_MANIFEST_SIZE
    ))

    register_swift_info('tlo')

    def tlo_filter(app):
        return TarLargeObject(
            app, conf,
            max_manifest_segments=max_manifest_segments,
            max_manifest_size=max_manifest_size)
    return tlo_filter
