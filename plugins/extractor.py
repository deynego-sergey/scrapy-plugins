# -*- coding:utf-8 -*-

#
# © sergey.deynego@gmail.ru
#

import json
import re

import demjson
from scrapy import Selector

#
#

KEY = 'page_objects'
BLANK_RE = type(re.compile(""))


class JsonExtractor(object):
    """
    Плагин предназначен для получения на лету данных из загруженной стриницы извлекаемых через xpath
    и обрабатываемых регулярными выражениями(или без них)
    Подключение к пауку:

    custom_settings = {
             'DOWNLOADER_MIDDLEWARES': {
                 'scrapyproject.extensions.extractors.JsonExtractor': 200,
                  }
         }

     Использование в запросе:
     Request(url=url, callback=callback, meta = {'page_objects':{'json':{'xpath':list, 'regexp':[]}}}
     page_objects - словарь, ключи которого содержат различные типы извлекаемых данных
    'default':{'xpath':[], 'regexp':[]}
    'json':{'xpath':[], 'regexp':[]}
    'links':{'xpath':[], 'regexp':[]}
    'img':{'xpath':[], 'regexp':[]}
    'texts':{'xpath':[], 'regexp':[]}
    и другие

    результаты для каждого ключа помещаются в поле result:[]
    """

    def process_response(self, request, response, spider):

        spider.logger.info("processing response: {}".format(response.url))
        if response.status in [200]:

            def _re_apply(regexp, src):
                try:
                    if isinstance(regexp, (str, BLANK_RE)):
                        try:
                            _reo = re.compile(regexp)
                        except:
                            _reo = regexp
                    return _reo.search(src).group()
                except Exception as e:
                    spider.logger.error("Error regexp apply url:{}".format(response.url))
                    return None

            def _json_ext(v):
                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    try:
                        return demjson.decode(v)
                    except:
                        spider.logger.error("Error json decode url:{} ".format(response.url))
                        return None

            def _extract(x):
                if isinstance(x, (tuple,)):
                    main_key = x[0]
                    d_dict = x[1]
                    xp_result = []
                    list(map(lambda m: xp_result.extend(m),
                             list(map(lambda item:
                                      list(filter(lambda item1: item1,
                                                  response.xpath(item).extract())),
                                      d_dict.get('xpath', [])))))
                    xp_result = list(set(xp_result))
                    o_result = []
                    list(map(lambda l: o_result.extend(l),
                             list(map(lambda s:
                                      list(map(lambda r:
                                               _re_apply(r, s),
                                               d_dict.get('regexp', []))),
                                      xp_result))))
                    if main_key.upper() in 'JSON':
                        o_result = list(map(_json_ext, o_result))
                    if main_key.upper() in 'LINKS':
                        pass
                    if main_key.upper() in 'DEFAULT':
                        pass
                    d_dict['result'] = list(map(lambda y: y, o_result))
                    return (main_key, d_dict)
                return x

            if KEY in list(request.meta.keys()):
                items_dict = request.meta[KEY]
                items = list(map(_extract, list(items_dict.items())))
                items_dict.update(items)
        return response


XP_KEY = 'xpath_obj'


class XPathExtractor(object):

    def process_response(self, request, response, spider):
        logger = logging.getLogger(spider.name + ' XPathExtractor')

        def _extract(selector, xpath_list):
            return None

        if XP_KEY in list(request.meta.keys()):
            html = re.sub(r'[\x00-\x1F\x7F]', '', response.text())
            html = Selector(text=html).xpath('//html/text()').extract_first(default='<html></html>')
            html = Selector(text=html)
            items_dict = request.meta[XP_KEY]
            items = list(map(_extract, list(items_dict.items())))
            items_dict.update(items)
        return response
