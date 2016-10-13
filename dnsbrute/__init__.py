from __future__ import absolute_import, print_function
from functools import partial
from collections import namedtuple
import os
import base64
import random
import logging
import json
import pycares
import pycares.errno
import gevent
import gevent.pool
from gevent import select
from gevent.event import AsyncResult
import progressbar


LOG = logging.getLogger(__name__)


def rand_name():
    return base64.b32encode(os.urandom(50))[:random.randint(5, 30)].lower()


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
                self.bruter.on_result(self.domain, dnsname, query_type, resp, None)
            except DNSError as ex:
                self.bruter.on_result(self.domain, dnsname, query_type, None, ex)


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
        self.wildcards = set([])
        self.options = options
        self.domains = []
        if options.domains:
            self.domains += filter(None, options.domains.read().split("\n"))
        self.domains += options.domain
        self.domains = list(set(self.domains))
        self.resolvers = map(str.strip, filter(None, options.resolvers.read().split("\n")))
        random.shuffle(self.resolvers)
        self.names = filter(None, options.names.read().split("\n"))
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
                 len(self.names), len(self.resolvers), len(self.domains))

    def valid(self):
        return len(self.domains) and len(self.resolvers) and len(self.names)

    def _print_result(self, dnsname, query_type, result):
        res_keys = ' '.join(['='.join([key, str(value)])
                             for key, value in result.items()])
        info = ' '.join([dnsname, query_type, res_keys])
        if not self.options.quiet:
            print(info)
        output = self.options.output
        if output:
            output.write(info + "\n")
            output.flush()
        outjson = self.options.json
        if outjson:
            outdict = result.copy()
            outdict['_type'] = query_type
            outdict['_name'] = dnsname
            if dnsname[0] == '*':
                outdict['_wildcard'] = True
            outjson.write(json.dumps(outdict) + "\n")


    def on_result(self, domain, dnsname, query_type, resp, error=None):
        """
        When a DNS name tester finds a result, it triggers this
        """
        if resp:
            results = self._format_results(query_type, resp)
            for _, result in results:
                if query_type not in ['A', 'AAAA'] or (domain, query_type, result['host']) not in self.wildcards:
                    self._print_result(dnsname, query_type, result)
        if self.progress:
            self.progress.update(self.finished)
        self.finished += 1

    def query(self, name, query_type):
        return DNSResolver.query(name, query_type, timeout=self.options.timeout,
                                 tries=self.options.retries, servers=self.resolvers)

    def _structseq_to_dict(self, obj):
        """
        Converts a structseq result from pycares module, into a dict
        """
        ignored_fields = ['n_fields', 'n_sequence_fields', 'n_unnamed_fields', 'ttl']
        fields = dict([(field, getattr(obj, field))
                       for field in dir(obj)
                       if field[0] != '_' and field not in ignored_fields])
        return fields

    def _format_result(self, query_type, resp):
        """
        Translates between Pycares result, and dnsbrute result
        Ignores the 'ttl' field, because that varies and we don't care about it
        """
        return (query_type, self._structseq_to_dict(resp))

    def _format_results(self, query_type, resp_list):
        if not isinstance(resp_list, list):
            resp_list = [resp_list]
        return [
            self._format_result(query_type, resp)
            for resp in resp_list
        ]

    def _find_wildcards(self):
        """
        Queries some random non-existant records to reduce false positives.
        """
        LOG.info("Eliminating wildcard responses from results")
        results = []
        for domain in self.domains:
            names = [rand_name(), rand_name(), rand_name()]
            for name in names:
                for query_type in ['A', 'AAAA']:
                    dnsname = name + '.' + domain
                    try:
                        resp = self.query(dnsname, query_type).get()
                    except DNSError:
                        continue
                    for result in self._format_results(query_type, resp):
                        LOG.debug('Found wildcard response: %r', result)
                        results.append((domain, result))
        wildcards = []
        for domain, (query_type, resp) in results:
            wildcards.append((domain, query_type, resp['host']))
            self._print_result('*.' + domain, query_type, resp)
        self.wildcards = set(wildcards)

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
    def query(cls, name, query_type, timeout=1.5, tries=2, servers=None):
        """Begin a DNS lookup. The result (or exception) will be in the
        returned :class:`~gevent.event.AsyncResult` when it is available.

        :param name: The DNS name to resolve.
        :type name: str
        :param query_type: The DNS query type, see
                           :meth:`pycares.Channel.query` for options. A string
                           may be given instead, e.g. ``'MX'``.
        :rtype: :class:`~gevent.event.AsyncResult`

        """
        if not servers:
            servers = ['8.8.4.4', '8.8.8.8']
        result = AsyncResult()
        query_type = cls._get_query_type(query_type)
        cls._channel = cls._channel or cls.channel or pycares.Channel(
            pycares.ARES_FLAG_NOSEARCH,  # flags
            timeout,
            tries,
            1,  # ndots
            53,  # tcp_port
            53,  # udp_port
            servers,
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
                rlist, wlist, _ = select.select(
                    read_fds, write_fds, [], timeout)
                for fd in rlist:
                    cls._channel.process_fd(fd, pycares.ARES_SOCKET_BAD)
                for fd in wlist:
                    cls._channel.process_fd(pycares.ARES_SOCKET_BAD, fd)
        except Exception:
            LOG.exception(__name__)
            cls._channel.cancel()
            cls._channel = None
            raise
        finally:
            cls._thread = None
