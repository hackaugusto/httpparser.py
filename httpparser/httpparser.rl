/**
 * This file is part of httpparse released under the BSD 3-Clause license.
 * See the NOTICE for more information.
 **/

#include <Python.h>
#include <structmember.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define LEN(AT, FPC)                (FPC - buf - self->AT)
#define MARK(M,FPC)                 (self->M = (FPC) - buf)
#define PTR_TO(F)                   (buf + self->F)
#define TO_PY_BYTES(PTR, LENGTH)    (Py_BuildValue("y#", PTR, LENGTH))
#define ALLOC_OR_FAIL(TARGET, CALL) { TARGET = CALL; if (TARGET == NULL) { goto fail; } }

%%{

    machine http_parser;

    action mark {
        MARK(mark, fpc);
    }

    action start_field {
        MARK(field_start, fpc);
    }

    action write_field {
        self->field_len = LEN(field_start, fpc);
    }

    action start_value {
        MARK(mark, fpc);
    }

    action write_value {
        // TODO: maximum number of headers
        // TODO: check ref count

        int content_length;
        PyObject *key;
        PyObject *value;

        key = TO_PY_BYTES(PTR_TO(field_start), self->field_len);
        value = TO_PY_BYTES(PTR_TO(mark), LEN(mark, fpc));

        // TODO: callback to clean the values?
        if (Py_SIZE(key) == strlen("content-length")) {
            PyObject* lower_key = PyObject_CallMethod(key, "lower", NULL);

            if (memcmp(PyBytes_AsString(lower_key), "content-length", strlen("content-length")) == 0) {
                content_length = atoi(PyBytes_AsString(value));
                value = Py_BuildValue("i", content_length);
                self->content_len = content_length;
            }
        }

        PyDict_SetItem(self->headers, key, value);
    }

    action xml {
        self->xml_sent = 1;
    }

    action json {
        self->json_sent = 1;
    }

    action start_query {
        MARK(query_start, fpc);
    }

    action done {
        if(self->xml_sent || self->json_sent) {
            self->body_start = PTR_TO(mark) - buf;
            // +1 includes the \0
            self->content_len = fpc - buf - self->body_start + 1;
        } else {
            self->body_start = fpc - buf + 1;
        }

        fbreak;
    }

    action http_version {
        self->http_version = TO_PY_BYTES(PTR_TO(mark), LEN(mark, fpc));
    }

    action request_method {
        self->request_method = TO_PY_BYTES(PTR_TO(mark), LEN(mark, fpc));
    }

    action request_uri {
        self->request_uri = TO_PY_BYTES(PTR_TO(mark), LEN(mark, fpc));
    }

    action request_path {
        self->request_path = TO_PY_BYTES(PTR_TO(mark), LEN(mark, fpc));
    }

    action query_string {
        self->query_string = TO_PY_BYTES(PTR_TO(mark), LEN(mark, fpc));
    }

    action fragment {
        self->fragment = TO_PY_BYTES(PTR_TO(mark), LEN(mark, fpc));
    }

# HTTP PROTOCOL GRAMMAR

    CRLF = ( "\r\n" | "\n" ) ;

# URI description as per RFC 3986.

    sub_delims    = ( "!" | "$" | "&" | "'" | "(" | ")" | "*"
                  | "+" | "," | ";" | "=" ) ;
    gen_delims    = ( ":" | "/" | "?" | "#" | "[" | "]" | "@" ) ;
    reserved      = ( gen_delims | sub_delims ) ;
    unreserved    = ( alpha | digit | "-" | "." | "_" | "~" ) ;

    pct_encoded   = ( "%" xdigit xdigit ) ;

    pchar         = ( unreserved | pct_encoded | sub_delims | ":" | "@" ) ;

    fragment      = ( ( pchar | "/" | "?" )* ) >mark %fragment ;

    query         = ( ( pchar | "/" | "?" )* ) %query_string ;

# non_zero_length segment without any colon ":" ) ;

    segment_nz_nc = ( ( unreserved | pct_encoded | sub_delims | "@" )+ ) ;
    segment_nz    = ( pchar+ ) ;
    segment       = ( pchar* ) ;

    path_empty    = ( pchar{0} ) ;
    path_rootless = ( segment_nz ( "/" segment )* ) ;
    path_noscheme = ( segment_nz_nc ( "/" segment )* ) ;
    path_absolute = ( "/" ( segment_nz ( "/" segment )* )? ) ;
    path_abempty  = ( ( "/" segment )* ) ;

    path          = ( path_abempty    # begins with "/" or is empty
                  | path_absolute   # begins with "/" but not "//"
                  | path_noscheme   # begins with a non-colon segment
                  | path_rootless   # begins with a segment
                  | path_empty      # zero characters
                  ) ;

    reg_name      = ( unreserved | pct_encoded | sub_delims )* ;

    dec_octet     = ( digit               # 0-9
                  | ("1"-"9") digit     # 10-99
                  | "1" digit{2}        # 100-199
                  | "2" ("0"-"4") digit # 200-249
                  | "25" ("0"-"5")      # 250-255
                  ) ;

    IPv4address   = ( dec_octet "." dec_octet "." dec_octet "." dec_octet ) ;
    h16           = ( xdigit{1,4} ) ;
    ls32          = ( ( h16 ":" h16 ) | IPv4address ) ;

    IPv6address   = (                               6( h16 ":" ) ls32
                  |                          "::" 5( h16 ":" ) ls32
                  | (                 h16 )? "::" 4( h16 ":" ) ls32
                  | ( ( h16 ":" ){1,} h16 )? "::" 3( h16 ":" ) ls32
                  | ( ( h16 ":" ){2,} h16 )? "::" 2( h16 ":" ) ls32
                  | ( ( h16 ":" ){3,} h16 )? "::"    h16 ":"   ls32
                  | ( ( h16 ":" ){4,} h16 )? "::"              ls32
                  | ( ( h16 ":" ){5,} h16 )? "::"              h16
                  | ( ( h16 ":" ){6,} h16 )? "::"
                  ) ;

    IPvFuture     = ( "v" xdigit+ "." ( unreserved | sub_delims | ":" )+ ) ;

    IP_literal    = ( "[" ( IPv6address | IPvFuture  ) "]" ) ;

    port          = ( digit* ) ;
    host          = ( IP_literal | IPv4address | reg_name ) ;
    userinfo      = ( ( unreserved | pct_encoded | sub_delims | ":" )* ) ;
    authority     = ( ( userinfo "@" )? host ( ":" port )? ) ;

    scheme        = ( alpha ( alpha | digit | "+" | "-" | "." )* ) ;

    relative_part = ( "//" authority path_abempty
                  | path_absolute
                  | path_noscheme
                  | path_empty
                  ) ;


    hier_part     = ( "//" authority path_abempty
                  | path_absolute
                  | path_rootless
                  | path_empty
                  ) ;

    absolute_URI  = ( scheme ":" hier_part ( "?" query )? ) ;

    relative_ref  = ( (relative_part %request_path ( "?" %start_query query )?) >mark %request_uri ( "#" fragment )? ) ;
    URI           = ( scheme ":" (hier_part  %request_path ( "?" %start_query query )?) >mark %request_uri ( "#" fragment )? ) ;

    URI_reference = ( URI | relative_ref ) ;

# HTTP header parsing

    Method = ( upper | digit ){1,20} >mark %request_method;

    http_number = ( "1." ("0" | "1") ) ;
    HTTP_Version = ( "HTTP/" http_number ) >mark %http_version ;
    Request_Line = ( Method " " URI_reference " " HTTP_Version CRLF ) ;

    HTTP_CTL = (0 - 31) | 127 ;
    HTTP_separator = ( "(" | ")" | "<" | ">" | "@"
                   | "," | ";" | ":" | "\\" | "\""
                   | "/" | "[" | "]" | "?" | "="
                   | "{" | "}" | " " | "\t"
                   ) ;

    lws = CRLF? (" " | "\t")+ ;
    token = ascii -- ( HTTP_CTL | HTTP_separator ) ;
    content = ((any -- HTTP_CTL) | lws);

    field_name = ( token )+ >start_field %write_field;

    field_value = content* >start_value %write_value;

    message_header = field_name ":" lws* field_value :> CRLF;

    Request = Request_Line ( message_header )* ( CRLF );

    SocketJSONStart = ("@" relative_part);
    SocketJSONData = "{" any* "}" :>> "\0";

    SocketXMLData = ("<" [a-z0-9A-Z\-.]+) >mark %request_path ("/" | space | ">") any* ">" :>> "\0";

    SocketJSON = SocketJSONStart >mark %request_path " " SocketJSONData >mark @json;
    SocketXML = SocketXMLData @xml;

    SocketRequest = (SocketXML | SocketJSON);

    main := (Request | SocketRequest) @done;

}%%

%% write data;

PyDoc_STRVAR(
    httpparser_doc,
    "A fast HTTP1.1 parser based on ragel"
);

static PyObject *ParseError;

static struct PyModuleDef httpparsermodule = {
   PyModuleDef_HEAD_INIT, /*     m_base */
   "httpparser",          /*     m_name */
   httpparser_doc,        /*      m_doc */
   0,                     /*     m_size */  /* no global state */
   NULL,                  /*  m_methods */
   NULL,                  /*    m_slots */
   NULL,                  /* m_traverse */
   NULL,                  /*    m_clear */
   NULL                   /*     m_free */
};

typedef struct {
    PyObject_HEAD
    PyObject *http_version;
    PyObject *request_method;
    PyObject *request_uri;
    PyObject *request_path;
    PyObject *query_string;
    PyObject *fragment;
    PyObject *headers;

    int cs;
    size_t body_start;
    int content_len;
    size_t nread;
    size_t mark;
    size_t field_start;
    size_t field_len;
    size_t query_start;
    int xml_sent;
    int json_sent;
} ParserObject;

static PyObject *
ParserObject_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    ParserObject *self;

    /* tp_alloc must zero the memory */
    self = (ParserObject *)type->tp_alloc(type, 0);

    if (self == NULL)
        return NULL;

    int cs = 0;
    %% write init;
    self->cs = cs;

    ALLOC_OR_FAIL(self->headers, PyDict_New());
    ALLOC_OR_FAIL(self->http_version, PyBytes_FromString(""));
    ALLOC_OR_FAIL(self->request_method, PyBytes_FromString(""));
    ALLOC_OR_FAIL(self->request_uri, PyBytes_FromString(""));
    ALLOC_OR_FAIL(self->request_path, PyBytes_FromString(""));
    ALLOC_OR_FAIL(self->query_string, PyBytes_FromString(""));
    ALLOC_OR_FAIL(self->fragment, PyBytes_FromString(""));
    return (PyObject *)self;

fail:
    Py_XDECREF(self->http_version);
    Py_XDECREF(self->request_method);
    Py_XDECREF(self->request_uri);
    Py_XDECREF(self->request_path);
    Py_XDECREF(self->query_string);
    Py_XDECREF(self->fragment);
    Py_XDECREF(self->headers);
    return NULL;
}

static void
ParserObject_dealloc(ParserObject* self)
{
    Py_XDECREF(self->http_version);
    Py_XDECREF(self->request_method);
    Py_XDECREF(self->request_uri);
    Py_XDECREF(self->request_path);
    Py_XDECREF(self->query_string);
    Py_XDECREF(self->fragment);
    Py_XDECREF(self->headers);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(
    object_parse_doc,
    "Receives a buffer of data and parses it, storing the parsed data in the object"
);

static PyObject *
ParserObject_parse(ParserObject* self, PyObject* args)
{

    int finished;
    Py_buffer py_buffer;
    char* buf;

    // The format "y" exports with the flag PyBUF_SIMPLE and checks that we get
    // a contiguous array
    if (!PyArg_ParseTuple(args, "y*:parse", &py_buffer))
        return NULL;

    buf = py_buffer.buf;

    int cs;     /* An integer with the current stats, must persist across invocations */
    char *p;    /* Data pointer to the beginning of the data block, it will be update by the machine */
    char *pe;   /* Data end pointer */

    cs = self->cs;
    p = py_buffer.buf + self->nread;
    pe = py_buffer.buf + py_buffer.len;

    %% write exec;

    assert(p <= pe && "Buffer overflow after parsing.");

    if (cs != http_parser_error) {
        self->cs = cs;
    }

    self->nread = p - buf;

    if (self->cs == http_parser_error) {
        finished = -1;
    } else if (self->cs >= http_parser_first_final) {
        finished = 1;
    } else {
        finished = 0;
    }

    PyBuffer_Release(&py_buffer);

    return Py_BuildValue("i",finished);
}

static PyMethodDef ParserObject_methods[] = {
    {
        "parse",                         /* ml_name */
        (PyCFunction)ParserObject_parse, /* ml_meth */
        METH_VARARGS,                    /* ml_flags */
        object_parse_doc                 /* ml_doc */
    },
    {NULL}  /* Sentinel */
};

static PyMemberDef ParserObject_members[] = {
    {
        "body_start",                       /* name */
        T_INT,                              /* type */
        offsetof(ParserObject, body_start), /* offset */
        0,                                  /* flags */ /* read-only or writable */
        "body_start"                        /* doc */
    },
    {"content_len", T_INT, offsetof(ParserObject, content_len), 0, "content_len"},
    {"nread", T_INT, offsetof(ParserObject, nread), 0, "nread"},
    {"xml_sent", T_INT, offsetof(ParserObject, xml_sent), 0, "xml_sent"},
    {"json_sent", T_INT, offsetof(ParserObject, json_sent), 0, "json_sent"},

    {"http_version", T_OBJECT, offsetof(ParserObject, http_version), 0, "http_version"},
    {"request_method", T_OBJECT, offsetof(ParserObject, request_method), 0, "request_method"},
    {"request_uri", T_OBJECT, offsetof(ParserObject, request_uri), 0, "request_uri"},
    {"request_path", T_OBJECT, offsetof(ParserObject, request_path), 0, "request_path"},
    {"query_string", T_OBJECT, offsetof(ParserObject, query_string), 0, "query_string"},
    {"fragment", T_OBJECT, offsetof(ParserObject, fragment), 0, "fragment"},
    {"headers", T_OBJECT, offsetof(ParserObject, headers), 0, "headers"},

    {NULL}  /* Sentinel */
};

PyDoc_STRVAR(parser_doc, "A Parser type capable of parsing HTTP1.1 requests");

static PyTypeObject ParserType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "httpparser.Parser",                      /*           tp_name */
    sizeof(ParserObject),                     /*      tp_basicsize */
    0,                                        /*       tp_itemsize */
    (destructor)ParserObject_dealloc,         /*        tp_dealloc */
    0,                                        /*          tp_print */
    0,                                        /*        tp_getattr */
    0,                                        /*        tp_setattr */
    0,                                        /*       tp_reserved */
    0,                                        /*           tp_repr */
    0,                                        /*      tp_as_number */
    0,                                        /*    tp_as_sequence */
    0,                                        /*     tp_as_mapping */
    0,                                        /*           tp_hash */
    0,                                        /*           tp_call */
    0,                                        /*            tp_str */
    0,                                        /*       tp_getattro */
    0,                                        /*       tp_setattro */
    0,                                        /*      tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*          tp_flags */
    parser_doc,                               /*            tp_doc */
    0,                                        /*       tp_traverse */
    0,                                        /*          tp_clear */
    0,                                        /*    tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /*           tp_iter */
    0,                                        /*       tp_iternext */
    ParserObject_methods,                     /*        tp_methods */
    ParserObject_members,                     /*        tp_members */
    0,                                        /*         tp_getset */
    0,                                        /*           tp_base */
    0,                                        /*           tp_dict */
    0,                                        /*      tp_descr_get */
    0,                                        /*      tp_descr_set */
    0,                                        /*     tp_dictoffset */
    (initproc)0,                              /*           tp_init */
    0,                                        /*          tp_alloc */
    ParserObject_new,                         /*            tp_new */
};

PyMODINIT_FUNC
PyInit_httpparser(void)
{
    PyObject *module = 0;

    if (PyType_Ready(&ParserType) < 0)
        return NULL;

    ALLOC_OR_FAIL(ParseError, PyErr_NewException("httparser.ParseError", NULL, NULL));
    ALLOC_OR_FAIL(module, PyModule_Create(&httpparsermodule));

    Py_INCREF(ParseError);
    Py_INCREF(&ParserType);
    PyModule_AddObject(module, "ParserError", (PyObject *)ParseError);
    PyModule_AddObject(module, "Parser", (PyObject *)&ParserType);
    return module;

fail:
    Py_XDECREF(module);
    Py_XDECREF(ParseError);
    return NULL;
}
