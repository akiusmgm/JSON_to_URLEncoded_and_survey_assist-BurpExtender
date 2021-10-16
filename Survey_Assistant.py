# This Python file uses the following encoding: utf-8

# 機能：
# ・URL、メソッド、パラメータ数　を、EXCELに貼り付けられる形式(TSV)でコピー
# ・パラメータの差分を表示
# ・JSON 形式のbodyを、x-www-form-urlencoded 形式に整形する。（CSRF検証用。変換機能が2に含まれるため、ついでに追加）

# リクエストの右クリックメニューに、
# 1. Extensions> Survey Assistant> Copy URL etc.
# 2. Extensions> Survey Assistant> Diff Params
# 3. Extensions> Survey Assistant> JSON to URLEncoded
# が追加される

# 1.:URL、メソッド、パラメータ数　を、EXCELに貼り付けられる形式(TSV)でコピー

# 2.:Extenderタブ内、本Extenderの「Output」に、前回実行時のリクエストとの、パラメータのdiff を表示する。

# 3. Repeater あたりにて、JSON 形式のbodyを、x-www-form-urlencoded 形式に整形する。
# （文字列以外のvalueも無理やり文字列にして変換するため、null が"None"、trueが"True"になるなどする。）

# ver.20211016
# jsonに対応。
# ついでに、CSRF検証で使えるよう、jsonパラメータをURLEncodedに書き換えるメニューを追加。
# ver.20211014
# 作成。
# コピーと差分機能

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

        else:
            params[_prefix] = _data

        return

    if type(json) is dict:
        for key, value in json.items():
            fn(params, key, value)
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

            contentType = requestInfo.getContentType()
            if contentType != requestInfo.CONTENT_TYPE_JSON:
                continue

            offset = requestInfo.getBodyOffset()
            json_dict = json.loads(self.helpers.bytesToString(req[offset:]))
            params = get_json_params(json_dict)

            body="&".join([key+"="+self.helpers.urlEncode(str(value)) for key,value in sorted(params.items())])
            # self.stdout.println(body)

            message.setRequest(req[:offset]+self.helpers.stringToBytes(body))

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
                    keys.append(param.getName())

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
