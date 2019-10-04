# -*- coding:utf-8 -*-

"""
DOWNLOADER_MIDDLEWARES for detection antiddos protection and browser checkng

"""
from scrapy.http import Response

SCRIPT = """
function main(splash, args)
  splash:go(args.url)
  assert(splash:wait(10))
  return {
    html = splash:html(),
    har = splash:har(),
  }
end
"""


class CloudFlareProtect(object):

    def __init__(self, script = '',  **kw):
        self._custom_script = script

    @classmethod
    def from_crawler(cls, crawler):
        return cls( script=crawler.settings.get('CF_SCRIPT', SCRIPT))

    def process_response(self, request, response, spider):
        """

        :param request: cookiejar = 'https://x.x.x.x:s'
        :param response:
        :param spider:
        :return:
        """
        if request.meta.get('splash', False):
            el = response.data['har']['log']['entries']
            cl = list(map(lambda c: c['response']['headers'],
                          filter(lambda x: '/cdn-cgi/l/chk_jschl' in x['request']['url'], el)))
            rq = request
            del rq.meta['splash']
            r = Response(url=request.url, request=rq, headers=headers, body=response.body)
            return r

        if response.headers.get('server') and response.status == 503:
            if '/cdn-cgi/l/chk_jschl' in response.xpath("//form/@action").get():
                #
                # process cloudflare
                #
                o = {
                    'args': {
                        'lua_source': self._custom_script),
                        'url': request.url
                    },
                    'html': 1,
                    'har': 1,
                    'lua_enabled': 1,
                    'endpoint': 'execute'
                }
                if request.meta.get('proxy', False):
                    o['args']['proxy'] = request.meta.get('proxy')
                r = request
                r.meta['splash'] = o
                return r
        return response




class BlazingFastProtect(object):
    pass
