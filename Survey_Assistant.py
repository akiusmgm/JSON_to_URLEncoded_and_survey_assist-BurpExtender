# This Python file uses the following encoding: utf-8

# 機能：
# 1. URL、メソッド、パラメータ数　を、EXCELに貼り付けられる形式(TSV)でコピー
# 2. パラメータの差分を表示
# 3. JSON 形式のbodyを、x-www-form-urlencoded 形式に整形する。（CSRF検証用）

# リクエストの右クリックメニューに、
# 1. Extensions> Survey Assistant> Copy URL etc.  
#     URL、メソッド、パラメータ数　を、EXCELに貼り付けられる形式(TSV)でコピー
# 2. Extensions> Survey Assistant> Diff Params  
#     Extenderタブ内、本Extenderの「Output」に、前回実行時のリクエストとの、パラメータの差分(unified_diff)を表示する。
# 3. Extensions> Survey Assistant> JSON to URLEncoded  
#     Repeater あたりにて、JSON 形式のbodyを、x-www-form-urlencoded 形式に整形する。      
#     （文字列以外のvalueも無理やり文字列にして変換するため、null が"null"、trueが"True"になるなどする。）
# が追加される

# ver.20211019
# 一部、日本語に対応。
# 機能3（jsonパラメータをURLEncodedに整形）にて、日本語などに対応、Content-Typeを更新するように。
#   ヘッダーに日本語が含まれる場合、Content-Typeの変換の処理にて、該当箇所が崩れる。
# 機能2（パラメータ差分表示）では、日本語などは文字コードを表示する。（現在の出力箇所へのマルチバイト文字の表示方法が不明なため。）
#   差分表示用のタブを追加すれば、日本語表示も可能だろうと思っているが、その需要があるか不明なため手を付けていない。
# 機能1（URLなどコピー）は、日本語非対応。`requestInfo.getUrl().toString()`で取得した時点で壊れているため、手の付け方がわからない。

# ver.20211016
# jsonに対応。
# ついでに、CSRF検証で使えるよう、jsonパラメータをURLEncodedに書き換えるメニューを追加。

# ver.20211014
# 作成。
# コピーと差分機能

from re import UNICODE
from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem
from java.io import PrintWriter

from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.awt import Toolkit

from difflib import unified_diff

import json

import sys
reload(sys)
sys.setdefaultencoding('utf-8')


def get_json_params(json):
    params = {}

    def fn(params, _prefix, _data):
        if type(_data) is dict:
            for key, value in _data.items():
                fn(params, _prefix + "[" + key + "]", value)

        elif type(_data) is list:
            for i, value in enumerate(_data):
                fn(params, _prefix + "[" + str(i) + "]", value)

        elif isinstance(_data, unicode):
            params[_prefix] = _data.encode('unicode-escape')
        elif type(_data) is int:
            params[_prefix] = _data
        elif type(_data) is bool:
            params[_prefix] = _data
        elif _data is None:
            params[_prefix] = "null"
        else:
            params[_prefix] = _data

        return

    if type(json) is dict:
        for key, value in json.items():
            fn(params, key.encode('unicode-escape'), value)
    elif type(json) is list:
        for i, value in enumerate(json):
            fn(params, "[" + str(i) + "]", value)

    return params

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def __init__(self):
        self.pre_keys = []

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName('Survey Assistant')
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        ret = []
        context = invocation.getInvocationContext()
        self.selected_message = invocation.getSelectedMessages()
        if len(self.selected_message):
            if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST \
                    or context == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST \
                    or context == invocation.CONTEXT_PROXY_HISTORY          \
                    or context == invocation.CONTEXT_TARGET_SITE_MAP_TABLE  \
                    or context == invocation.CONTEXT_SEARCH_RESULTS:
                ret.append(JMenuItem('Copy URL etc.',
                           actionPerformed=self.copy_URL_etc))
                ret.append(JMenuItem('Diff Params',
                           actionPerformed=self.diff_params))

            if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                ret.append(JMenuItem('JSON to URLEncoded',
                           actionPerformed=self.json_to_urlencoded))

            return ret
        else:
            return None




    def json_to_urlencoded(self, e):
        for message in self.selected_message:
            req = message.getRequest()
            requestInfo = self.helpers.analyzeRequest(
                message.getHttpService(), req)
            headers = requestInfo.getHeaders()
            headersArray = list(headers)


            contentType = requestInfo.getContentType()
            if contentType != requestInfo.CONTENT_TYPE_JSON:
                continue

            for i, h in enumerate(headersArray):
                if h.lower().find("content-type:") == 0:
                    headersArray.pop(i)
            headersArray.append(
                "Content-Type: application/x-www-form-urlencoded")

            offset = requestInfo.getBodyOffset()
            json_dict = json.loads(self.helpers.bytesToString(req[offset:]))
            params = get_json_params(json_dict)

            body="&".join([key+"="+self.helpers.urlEncode(str(value)) for key,value in sorted(params.items())])

            body_bytes=self.helpers.stringToBytes(body.decode('unicode-escape'))

            out_req = self.helpers.buildHttpMessage(headersArray, body_bytes)
            message.setRequest(out_req)

        return

    def copy_URL_etc(self, e):
        for message in self.selected_message:
            requestInfo = self.helpers.analyzeRequest(
                message.getHttpService(), message.getRequest())

            method = requestInfo.getMethod()
            url = requestInfo.getUrl().toString()
            params = requestInfo.getParameters()
            num = sum(int(param.PARAM_COOKIE != param.getType())
                      for param in params)
            out = url+"\t"+method+"\t"+str(num)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(out), None)

        return

    def diff_params(self, e):
        for message in self.selected_message:
            req=message.getRequest()
            requestInfo = self.helpers.analyzeRequest(
                message.getHttpService(), req)

            is_json = False
            contentType = requestInfo.getContentType()
            if contentType == requestInfo.CONTENT_TYPE_JSON:
                is_json = True

            params = requestInfo.getParameters()
            keys = []
            for param in params:
                if (param.PARAM_COOKIE != param.getType()) \
                        and (param.PARAM_JSON != param.getType()):
                    keys.append(param.getName().encode('unicode-escape'))

            keys.sort()

            if is_json:
                keys_in_json = []
                offset = requestInfo.getBodyOffset()
                json_dict = json.loads(self.helpers.bytesToString(req[offset:]))
                params = get_json_params(json_dict)
                for key in params.keys():
                    keys_in_json.append(key)
                keys_in_json.sort()
                keys += keys_in_json

            self.stdout.println("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
            is_diff=False
            for line in unified_diff(self.pre_keys, keys, fromfile='before', tofile='after', n=999):
                is_diff=True
                self.stdout.println(line)
            if not is_diff:
                self.stdout.println("No difference in param names")

            self.stdout.println("//////////////////////////////")
            self.pre_keys = keys

        return
