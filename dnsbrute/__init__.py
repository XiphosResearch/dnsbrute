from __future__ import absolute_import, print_function
from functools import partial
from collections import namedtuple
import os
import base64
import random
import logging
import pycares
import pycares.errno
import gevent
import gevent.pool
from gevent import select
from gevent.event import AsyncResult
import progressbar


LOG = logging.getLogger(__name__)


SimpleResult = namedtuple('SimpleResult', ['host'])
CnameResult = namedtuple('CnameResult', ['cname'])
MxResult = namedtuple('MxResult', ['host', 'priority'])
NsResult = namedtuple('NsResult', ['host'])
SoaResult = namedtuple('SoaResult', ['nsname', 'hostmaster', 'serial',
                                     'refresh', 'retry', 'expires', 'minttl'])
SrvResult = namedtuple('SrvResult', ['host', 'port', 'priority', 'weight'])
TxtResult = namedtuple('TextResult', ['host'])

def rand_name():
    return base64.b32encode(os.urandom(50))[:random.randint(5,30)].lower()


class DNSNameTester(object):
    __slots__ = ('bruter', 'domain', 'name')

    def __init__(self, bruter, domain, name=None):
        self.bruter = bruter
        self.domain = domain
        self.name = name

    def run(self):
        lookups = ['CNAME', 'A', 'AAAA']
        dnsname = self.domain
        if self.name is None:
            lookups.append('MX')
            lookups.append('SOA')
            lookups.append('NS')
        else:
            dnsname = '.'.join([self.name, dnsname])
        for query_type in lookups:
            try:
                resp = self.bruter.query(dnsname, query_type).get()
                self.bruter.result(self.domain, dnsname, query_type, resp, None)
            except DNSError as ex:
                self.bruter.result(self.domain, dnsname, query_type, None, ex)


class DNSTesterGenerator(object):
    def __init__(self, bruter, domains, names):
        self.bruter = bruter
        self.domains = domains
        self.names = names
        self.total = len(self.domains) * len(self.names)

    def all(self):
        for domain in self.domains:
            yield DNSNameTester(self.bruter, domain)
            for name in self.names:
                yield DNSNameTester(self.bruter, domain, name)


class DNSBrute(object):
    def __init__(self, options):
        self.wildcards = []
        self.options = options
        self.domains = []
        if options.domains:
            self.domains += filter(None, options.domains.read().split("\n"))
        self.domains += options.domain
        self.domains = list(set(self.domains))
        resolvers = map(str.strip, filter(None, options.resolvers.read().split("\n")))
        random.shuffle(resolvers)
        self.names = filter(None, options.names.read().split("\n"))
        self.pycares_opts = dict(
            tries=options.retries,
            timeout=options.timeout,
            domains=[],
            lookup='b',
            servers=resolvers,
        )
        if options.progress:
            self.progress = progressbar.ProgressBar(
                redirect_stdout=True,
                widgets=[
                    progressbar.Bar(),
                    ' (', progressbar.ETA(), ') ',
                ])
        else:
            self.progress = None
        self.finished = 0
        LOG.info("%d names, %d resolvers, %d domains",
            len(self.names), len(resolvers), len(self.domains))

    def valid(self):
        return len(self.domains) > 0

    def _print_result(self, dnsname, query_type, result):
        res_keys = ' '.join(['='.join([field, str(getattr(result, field))])
                             for field in result._fields])
        print(' '.join([dnsname, query_type, res_keys]))

    def result(self, domain, dnsname, query_type, resp, error):
        if resp:
            results = self._format_results(query_type, resp)
            for _, result in results:
                if (domain, result) not in self.wildcards:
                    self._print_result(dnsname, query_type, result)                    
        if self.progress:
            self.progress.update(self.finished)
        self.finished += 1

    def query(self, name, query_type):
        return DNSResolver.query(name, query_type, pycares_opts=self.pycares_opts)

    def _format_result(self, query_type, resp):
        if isinstance(resp, pycares.ares_query_simple_result):
            return (query_type, SimpleResult(resp.host))
        elif isinstance(resp, pycares.ares_query_cname_result):
            return (query_type, CnameResult(resp.cname))
        elif isinstance(resp, pycares.ares_query_mx_result):
            return (query_type, MxResult(resp.host, resp.priority))
        elif isinstance(resp, pycares.ares_query_ns_result):
            return (query_type, NsResult(resp.host))
        elif isinstance(resp, pycares.ares_query_soa_result):
            return (query_type, SoaResult(resp.nsname, resp.hostmaster, resp.serial,
                                          resp.refresh, resp.retry, resp.expires, resp.minttl))
        elif isinstance(resp, pycares.ares_query_srv_result):
            return (query_type, SrvResult(resp.host, resp.port, resp.priority,
                                          resp.weight))
        elif isinstance(resp, pycares.ares_query_txt_result):
            return (query_type, TxtResult(resp.text))
        return (query_type, resp)

    def _format_results(self, query_type, resp_list):
        if not isinstance(resp_list, list):
            resp_list = [resp_list]
        return [
            self._format_result(query_type, resp)
            for resp in resp_list
        ]

    def _find_wildcards(self):
        LOG.info("Checking for wildcard responses to eliminate from results")
        results = []
        for domain in self.domains:
            names = [rand_name(), rand_name(), rand_name()]
            for name in names:
                for query_type in ['A', 'AAAA', 'CNAME']:
                    dnsname = name + '.' + domain
                    try:
                        resp = self.query(dnsname, query_type).get()
                    except DNSError as ex:
                        continue
                    for result in self._format_results(query_type, resp):
                        results.append((domain, result))
        results = set(results)
        wildcards = []
        for domain, (query_type, resp) in results:
            wildcards.append((domain, resp))
            self._print_result('*.' + domain, query_type, resp)
        self.wildcards = wildcards

    def run(self):
        self._find_wildcards()
        pool = gevent.pool.Pool(self.options.concurrency)
        namegen = DNSTesterGenerator(self, self.domains, self.names)
        if self.progress:
            self.progress.start()
        try:
            iterator = namegen.all()
            if self.progress:
                iterator = self.progress(iterator, namegen.total)
            for tester in iterator:
                pool.add(gevent.spawn(tester.run))
        except KeyboardInterrupt:
            print("Ctrl+C caught... stopping")
            pool.join()


class DNSError(Exception):
    """Exception raised with DNS resolution failed. The exception message will
    contain more information.

    .. attribute:: errno

       The error number, as per :mod:`pycares.errno`.

    """

    def __init__(self, errno):
        msg = '{0} [{1}]'.format(pycares.errno.strerror(errno),
                                 pycares.errno.errorcode[errno])
        super(DNSError, self).__init__(msg)
        self.errno = errno



class DNSResolver(object):
    """Manages all the active DNS queries using a single, static
    :class:`pycares.Channel` object.

    .. attribute:: channel

       Before making any queries, this attribute may be set to override the
       default with a :class:`pycares.Channel` object that will manage all DNS
       queries.

    """

    channel = None
    _channel = None
    _thread = None

    @classmethod
    def query(cls, name, query_type, pycares_opts=None):
        """Begin a DNS lookup. The result (or exception) will be in the
        returned :class:`~gevent.event.AsyncResult` when it is available.

        :param name: The DNS name to resolve.
        :type name: str
        :param query_type: The DNS query type, see
                           :meth:`pycares.Channel.query` for options. A string
                           may be given instead, e.g. ``'MX'``.
        :rtype: :class:`~gevent.event.AsyncResult`

        """
        if not pycares_opts:
            pycares_opts = dict()
        result = AsyncResult()
        query_type = cls._get_query_type(query_type)
        if pycares_opts is None:
            pycares_opts = dict()
        cls._channel = cls._channel or cls.channel or pycares.Channel(
            pycares.ARES_FLAG_NOSEARCH,  # flags
            pycares_opts['timeout'],
            pycares_opts['tries'],
            1,  # ndots
            53,  # tcp_port
            53,  # udp_port
            pycares_opts['servers'],
            [],  # domains
            'b')  # lookup
        cls._channel.query(name, query_type, partial(cls._result_cb, result))
        cls._thread = cls._thread or gevent.spawn(cls._wait_channel)
        return result

    @classmethod
    def _get_query_type(cls, query_type):
        if isinstance(query_type, str):
            type_attr = 'QUERY_TYPE_{0}'.format(query_type.upper())
            return getattr(pycares, type_attr)
        return query_type

    @classmethod
    def _result_cb(cls, result, answer, errno):
        if errno:
            exc = DNSError(errno)
            result.set_exception(exc)
        else:
            result.set(answer)

    @classmethod
    def _wait_channel(cls):
        try:
            while True:
                read_fds, write_fds = cls._channel.getsock()
                if not read_fds and not write_fds:
                    break
                timeout = cls._channel.timeout()
                if not timeout:
                    cls._channel.process_fd(pycares.ARES_SOCKET_BAD,
                                            pycares.ARES_SOCKET_BAD)
                    continue
                rlist, wlist, xlist = select.select(
                    read_fds, write_fds, [], timeout)
                for fd in rlist:
                    cls._channel.process_fd(fd, pycares.ARES_SOCKET_BAD)
                for fd in wlist:
                    cls._channel.process_fd(pycares.ARES_SOCKET_BAD, fd)
        except Exception:
            logging.log_exception(__name__)
            cls._channel.cancel()
            cls._channel = None
            raise
        finally:
            cls._thread = None
