# -*- coding:utf-8 -*-

#
# (c) sergey.deynego@gmail.com
#
#
import logging
import re
import urllib

import requests
from scrapy.exceptions import NotConfigured

# from scrapy.signals import spider_error,response_received

logger = logging.getLogger(__name__)


class ProxyNotLoadedException(Exception):
    pass


class SimpleProxyRotator(object):
    """
    Этот плагин работает со списком прокси (HTTP/HTTPS)
    Работает совместно с HttpProxyMiddleware

    'PROXY_TOTAL_COUNT', 100,
    'PROXY_REGION_FULL':None,
    'PROXY_REGION_CODE':
    'PROXY_RANGE': 8,
    'PROXY_TOP_RANGE', 10,
    'PROXY_SOURCE_DATA', None,
    'PROXY_TYPES', 3,
    'PROXY_POOL_SIZE', 5,
    'PROXY_ACCESS' : None -ТОКЕН ДЛЯ ДОСТУПА
    """

    SERVICE_URL = "http://proxy_service_url"

    def __init__(self, plist=list(), psize=5, pattempt=1, ptotal=100, ptype=2, prange=8, use_session=False, token=None):
        self.upload_params = None
        self._token = token
        self.sessions = dict() if use_session else None
        self._proxy_pool = set(plist)
        self._work_pool = {}
        self._pool_size = psize
        self._proxy_total = ptotal
        self._proxy_type = ptype
        self._proxy_range = prange
        self._fill_work_pool()
        self._max_attempt = pattempt

    @classmethod
    def from_crawler(cls, crawler):
        logger.info("Start create SimpleProxyExtension for crawler")
        token = crawler.settings.get('PROXY_TOKEN', None)
        try:
            p = [('count', crawler.settings.getint('PROXY_TOTAL_COUNT', 100)),
                 ('region', crawler.settings.get('PROXY_REGION_FULL', None)),
                 ('region_code', crawler.settings.get('PROXY_REGION_CODE', None)),
                 ('min_rate', crawler.settings.getint('PROXY_RANGE', 8)),
                 ('max_rate', crawler.settings.getint('PROXY_TOP_RANGE', 10)),
                 ('source', crawler.settings.get('PROXY_SOURCE_DATA', None)),
                 ('type', crawler.settings.getint('PROXY_TYPES', 3))]
            t = crawler.settings.get('PROXY_ACCESS', '')
            p = dict(filter(lambda x: x[1], p))
            l = cls._load_proxy(token=t, **p)  # son.loads(response.text)
            spider = cls(
                plist=l,  # crawler.settings.get('PROXY_LIST', ''),
                psize=crawler.settings.getint('PROXY_POOL_SIZE', 5),
                pattempt=crawler.settings.getint('PROXY_ERR_ATTEMPT', 3),
                ptotal=crawler.settings.getint('PROXY_TOTAL_COUNT', 100),
                ptype=crawler.settings.getint('PROXY_TYPES', 3),
                prange=crawler.settings.getint('PROXY_RANGE', 8),
                use_session=crawler.settings.getbool('COOKIES_ENABLED', False),
                token=t
            )
            # pass
            # spider['upload_params'] = p
            # spider['sessions'] = dict() if crawler.settings.getbool('COOKIES_ENABLED', False) else None
            return spider
        except Exception as err:
            logger.error("Bad Response from service")
            raise NotConfigured()

    def process_request(self, request, spider):

        if 'proxy_pause' in request.meta:
            self._update_err_proxy(request.meta['proxy_pause'], rotate=True)
            request.meta['proxy'] = "{}://{}".format(self._scheme(request.url), self._select_proxy(spider))
            del request.meta['proxy_pause']
            # return  # request

        if 'proxy_drop' in request.meta:
            self._update_err_proxy(request.meta['proxy_drop'], rotate=True)
            request.meta['proxy'] = "{}://{}".format(self._scheme(request.url), self._select_proxy(spider))
            del request.meta['proxy_drop']

        if 'proxy' not in request.meta:
            request.meta['proxy'] = "{}://{}".format(self._scheme(request.url), self._select_proxy(spider))

        if isinstance(self.sessions, dict):
            k = re.sub(r'^[^\d]*', '', request.meta.get('proxy', ''))
            session = self.sessions.get(k)
            request.meta['cookiejar'] = session['c']
            request.headers.update(session['h'])
        return  # request

    def process_response(self, request, response, spider):
        if 'proxy' in request.meta and response.status in [500, 501, 502, 503, 504, 403, 429, 507, 521]:
            p = request.meta['proxy']
            self._update_err_proxy(p, rotate=True)
            request.meta['proxy'] = "{}://{}".format(self._scheme(request.url), self._select_proxy(spider))
            return request
        return response

    def process_exception(self, request, exception, spider):
        p = request.meta.get('proxy', None)
        self._update_err_proxy(p)
        request.meta['proxy'] = "{}://{}".format(self._scheme(request.url), self._select_proxy(spider))
        return request

    def handleErr(self, failure, response, spider):
        pass

    def handleResponse(self, response, request, spider):
        pass

    def _load_proxy_list(self, path):
        if isinstance(path, list):
            return path
        return list(filter(lambda y: len(y),
                           map(lambda x: x.strip(), path.splitlines())))

    def _select_proxy(self, spider=None):
        k = min(self._work_pool, key=lambda x: self._work_pool.get(x).get('selected'))
        self._work_pool[k]['selected'] += 1
        if spider and len(self._proxy_pool) < len(self._work_pool):
            self._get_proxies(spider)
        return k

    def _get_proxy(self):
        p = self._proxy_pool.pop()
        if isinstance(self.sessions, dict) and not self.sessions.get(p, False):
            k = re.sub(r'^[^\d]*', '', p)
            self.sessions[k] = {'c': k, 'h': {}}
        return p

    def _update_err_proxy(self, proxy, rotate=False):
        key = re.sub(r'^[^\d]*', '', proxy)
        if key in self._work_pool:
            self._work_pool[key]['err'] += 1
            if rotate:
                self._proxy_pool.add(key)
                del self._work_pool[key]
            self._clear_work_pool()

    def _clear_work_pool(self):
        self._work_pool = dict(list(filter(lambda x: x[1]['err'] < self._max_attempt,
                                           list(self._work_pool.items()))))
        self._fill_work_pool()

    def _fill_work_pool(self):
        self._work_pool.update(
            [(self._get_proxy(), {'selected': 0, 'err': 0}) for x in range(0, self._pool_size - len(self._work_pool))])

    def _get_proxies(self, spider):
        p = dict(filter(lambda x: x[1], [('count', spider.settings.getint('PROXY_TOTAL_COUNT', 100)),
                                         ('region', spider.settings.get('PROXY_REGION_FULL', None)),
                                         ('region_code', spider.settings.get('PROXY_REGION_CODE', None)),
                                         ('min_rate', spider.settings.getint('PROXY_RANGE', 8)),
                                         ('max_rate', spider.settings.getint('PROXY_TOP_RANGE', 10)),
                                         ('source', spider.settings.get('PROXY_SOURCE_DATA', None)),
                                         ('type', spider.settings.getint('PROXY_TYPES', 3))]))
        l = self._load_proxy(self._token, **p)
        self._proxy_pool.update(set(l))

    def _scheme(self, url):
        return urllib.parse.urlparse(url).scheme

    @classmethod
    def _load_proxy(cls, token='', **kw):
        params = urllib.parse.urlencode(kw)
        r = requests.get(url="{}/getproxy/?{}".format(SERVICE_URL, params),
                         headers={'Accept': 'application/json', 'authorization': token})
        if r.status_code != 200:
            raise ProxyNotLoadedException()
        o = r.json()
        return list(map(lambda x: "{}:{}".format(x.get('ip'), x.get('port')), o))

# =======================================================================================+
#
#
# =======================================================================================+
