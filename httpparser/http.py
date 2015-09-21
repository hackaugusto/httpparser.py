# -*- coding: utf8 -*-
#
# This file is part of httpparse released under the BSD 3-Clause license.
# See the NOTICE for more information.
import re
import socket
import sys

try:
    from urlparse import urlsplit
except ImportError:
    from urllib.parse import urlsplit

#
#   Various ad hoc limitations on request-line length are found in practice.
#   It is RECOMMENDED that all HTTP senders and recipients support, at a
#   minimum, request-line lengths of 8000 octets.
#
# https://tools.ietf.org/html/rfc7230#section-3.1.1
MAX_REQUEST_LINE = 2 ** 13
MAX_HEADERS = 2 ** 15
MAX_PORT = 65535

HEADER_REGEX = re.compile('[\x00-\x1F\x7F()<>@,;:\[\]={} \t\\\\\"]')
VERSION_REGEX = re.compile(r'HTTP/(\d+)[.](\d+)')
# XXX: \s might be to broad (HTTP/1.1 spect talks only about \x20 SPACE and \x09 HT
STARTSPACE_REGEX = re.compile(r'^\s+')
ENDSPACE_REGEX = re.compile(r'\s+$')
RECV_SIZE = 2048


# Python's split method is fine:
#
#     ... recipients MAY parse on whitespace-delimited word boundaries and, aside
#     from the CRLF terminator, treat any form of whitespace as the SP separator
#     while ignoring preceding or trailing whitespace ...
#
# https://tools.ietf.org/html/rfc7230#section-3.5

# https://www.iana.org/assignments/http-methods/http-methods.xhtml
IANA_METHODS = (
    'ACL',
    'BASELINE-CONTROL',
    'BIND',
    'CHECKIN',
    'CHECKOUT',
    'CONNECT',
    'COPY',
    'DELETE',
    'GET',
    'HEAD',
    'LABEL',
    'LINK',
    'LOCK',
    'MERGE',
    'MKACTIVITY',
    'MKCALENDAR',
    'MKCOL',
    'MKREDIRECTREF',
    'MKWORKSPACE',
    'MOVE',
    'OPTIONS',
    'ORDERPATCH',
    'PATCH',
    'POST',
    'PROPFIND',
    'PROPPATCH',
    'PUT',
    'REBIND',
    'REPORT',
    'SEARCH',
    'TRACE',
    'UNBIND',
    'UNCHECKOUT',
    'UNLINK',
    'UNLOCK',
    'UPDATE',
    'UPDATEREDIRECTREF',
    'VERSION-CONTROL',
)


def generator_recv(sock):
    '''Read `RECV_SIZE` chunks of data from the `sock` while the socket is open'''
    data = sock.recv(RECV_SIZE)

    while data:
        yield data
        data = sock.recv(RECV_SIZE)

    # Assume that when no more data is received the other end closed the
    # connection
    raise StopIteration


def dosline_and_state(chunks, state=None, limit=MAX_REQUEST_LINE):
    '''
    Iterate over the `chunks` of data looking for the value `\r\n`, the
    function stops when:

    - `\r\n` is found, returning a 2-tuple:
        (<data up to `\r\n` including>, <remaining of the chunk data>)
    - the total size of the cosumed data is greater that limit

    Note that the function might consume [1,len(biggest chunk)) bytes of data
    past `limit`.
    '''
    # keep the \r\n because the parser might accept continuation lines
    idx = 0
    length = 0
    carriage = False
    parts = []

    if state:
        idx = state.find(b'\r\n')
        length = len(state)

        if idx:
            return (state[:idx+2], state[idx+2:])

        if length > limit:
            raise Exception()

        carriage = state.endswith(b'\r')
        parts.append(state)

    for data in chunks:
        if carriage and data.startswith(b'\n'):
            parts.push(b'\n')
            data = data[1:]
            break

        idx = data.find(b'\r\n')
        if idx:
            parts.append(data[:idx+2])
            data = data[idx+2:]
            break

        length += len(data)
        if length > limit:
            raise Exception()

        carriage = data.endswith(b'\r')
        parts.append(data)

    return (b''.join(parts), data)


def parse_from_socket(socket, ips_allowed_proxy):
    ip = socket.getpeername()[0]
    chunks = generator_recv(socket)

    # XXX: why? (different from gunicorn)
    if '*' in ips_allowed_proxy or ip in ips_allowed_proxy:
        return parse_maybe_proxy_and_state(chunks)

    return parse_and_state(chunks)


def parse_maybe_proxy_and_state(chunks, state):
    line, state = dosline_and_state(chunks, state)

    # TODO:
    # if line.startswith('PROXY'):
    #     proxy = parse_proxy(line[:-2])
    #     return parse_and_state(chunks, state)

    return parse_and_state(chunks, line + state)


def parse_and_state(chunks, state):
    # this parser is different from tornado's and gunicorn's for a couple of
    # reasons:
    # - we don't do continuation-headers
    # - we consider only lines ending with \r\n, \n is not a valid separator (tornado uses splitlines())
    # - we stream the data in chunks instead of buffering (gunicorn copies the
    #   buffers a few times, both buffer all headers)
    # - we reject headers with white space in the name (both allow continuation lines and ignore space after the name)
    # - other details that are documented with the relevant(s) RFCs throught out the code

    line_crlf, state = dosline_and_state(chunks, state)
    request = parse_request_line(line_crlf[:-2])
    i = 1

    line_crlf, state = dosline_and_state(chunks, state)

    # ... A recipient that receives whitespace between the start-line and the
    # first header field MUST either reject the message as invalid ...
    # https://tools.ietf.org/html/rfc7230#section-3
    if STARTSPACE_REGEX.match(line_crlf):
        raise Exception()

    headers = []
    while line_crlf != b'\r\n':
        i += 1

        if i > MAX_HEADERS:
            raise Exception()

        headers.append(parse_header(line_crlf[:-2]))

        line_crlf, state = dosline_and_state(chunks, state)

    return request, headers, state


def parse_proxy(line):
    # PROXY PROTO SADDR DADDR SPORT DPORT
    pieces = line.split()

    if len(pieces) != 6:
        raise Exception()

    __, proto, s_addr, d_addr, s_port, d_port = pieces

    if proto == 'TCP4':
        family = socket.AF_INET
    elif proto == 'TCP6':
        family = socket.AF_INET6
    else:
        raise Exception()

    try:
        socket.inet_pton(family, s_addr)
        socket.inet_pton(family, d_addr)
    except socket.error:
        raise Exception()

    try:
        s_port = int(s_port)
        d_port = int(d_port)
    except ValueError:
        raise Exception()

    if s_port > MAX_PORT or d_port > MAX_PORT or s_port < 0 or d_port < 0:
        raise Exception()

    return {
        'proxy_protocol': proto,
        'client_addr': s_addr,
        'client_port': s_port,
        'proxy_addr': d_addr,
        'proxy_port': d_port
    }


def parse_request_line(line):
    # https://tools.ietf.org/html/rfc7230#section-3.1.1 Request Line
    # https://tools.ietf.org/html/rfc7231#section-4 Request Methods
    # https://tools.ietf.org/html/rfc7230#section-5.3 Request Target
    # https://tools.ietf.org/html/rfc7230#section-2.6 Protocol Versioning

    #  request-line = method SP request-target SP HTTP-version CRLF
    pieces = line.split()

    # the fields are separated by single space
    # if '  ' in line:
    #     raise Exception()

    if len(pieces) != 3:
        raise Exception()

    method, target, version = pieces

    # The method token is case-sensitive because it might be used as a gateway
    # to object-based systems with case-sensitive method names.
    # https://tools.ietf.org/html/rfc7231#section-4
    if method not in IANA_METHODS:
        raise Exception()

    # URI - http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
    # When the path starts with //, urlsplit considers it as a relative target
    # while the RDF says it shouldnt considers it as an absolute url.
    if target.startswith('//'):
        target = target[1:]
    parts = urlsplit(target)

    match = VERSION_REGEX.match(parts[2])
    if match is None:
        raise Exception()

    return {
        'path': parts.path or '',
        'query': parts.query or '',
        'fragment': parts.fragment or '',
        'version': (int(match.group(1)), int(match.group(2))),
    }


def parse_header(line):
    # https://tools.ietf.org/html/rfc7230#section-3.2.4
    #
    # grammar:
    #   header-field   = field-name ":" OWS field-value OWS
    #   field-name     = token
    #   field-value    = *( field-content / obs-fold )
    #   field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
    #   field-vchar    = VCHAR / obs-text
    #   obs-fold       = CRLF 1*( SP / HTAB ) ; obsolete line folding, see Section 3.2.4

    if ':' not in line:
        raise Exception()

    name, value = line.split(':', 1)

    # A server that receives an obs-fold in a request message that is not
    # within a message/http container MUST either reject the message by sending
    # a 400 (Bad Request), preferably with a representation explaining that
    # obsolete line folding is unacceptable, ...
    if STARTSPACE_REGEX.match(name):
        raise Exception()

    # No whitespace is allowed between the header field-name and colon. In the
    # past, differences in the handling of such whitespace have led to security
    # vulnerabilities in request routing and response handling. A server MUST
    # reject any received request message that contains whitespace between a
    # header field-name and colon with a response code of 400 (Bad Request).  A
    # proxy MUST remove any such whitespace from a response message before
    # forwarding the message downstream.
    if ENDSPACE_REGEX.search(name):
        raise Exception()

    # field-name is case insenstive
    name = name.upper()
    if HEADER_REGEX.match(name):
        raise Exception()

    return (name, value.strip())


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', action='store_true', default=False, help='flag to run the tests')
    parser.add_argument('--failfast', action='store_true', default=False, help='unittest failfast')
    args = parser.parse_args()

    if args.test:
        import doctest
        (failures, total) = doctest.testmod()

        if failures:
            sys.exit(failures)
