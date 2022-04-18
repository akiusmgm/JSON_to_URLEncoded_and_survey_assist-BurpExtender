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
#     （文字列以外のvalueも無理やり文字列にして変換するため、null が"None"、trueが"True"になるなどする。）
# が追加される

# ver.20211019
# 一部、日本語に対応。
# 機能3（jsonパラメータをURLEncodedに整形）にて、日本語に対応。
# パラメータ差分表示では、文字コード（shift-jis）を表示するようにした。（現在の出力箇所へのマルチバイト文字の表示方法が不明なため。）
# ver.20211016
# jsonに対応。
# ついでに、CSRF検証で使えるよう、jsonパラメータをURLEncodedに書き換えるメニューを追加。
# ver.20211014
# 作成。
# コピーと差分機能

import re
from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem
from java.io import PrintWriter

from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.awt import Toolkit

from difflib import unified_diff

import json
from jarray import array

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

schemes = {
    "http": 80,
    "https": 443
}


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

            json_dict = json.loads(bytes_to_string_esc_shift_jis(req[offset:]))
            params = get_json_params(json_dict)

            body = "&".join([key+"="+self.helpers.urlEncode(str(value))
                            for key, value in sorted(params.items())])
            # self.stdout.println(body)

            body_bytes = array(string_to_bytes_unesc_shift_jis(body), 'b')
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

            scheme=re.search("^(\w+)://.*",url).group(1)
            port=int(re.search("^\w+://[^:/]+:(\d+)/.*$",url).group(1))
            if scheme in schemes and schemes[scheme]==port:
                url=re.sub("^(\w+://[^:/]+):(\d+)(/.*)$",r"\1\3",url)
            #     self.stdout.println("scheme: "+scheme)
            #     self.stdout.println("port: "+str(port))
            # self.stdout.println("url: "+url)

            out = url+"\t"+method+"\t"+str(num)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(out), None)

        return

    def diff_params(self, e):
        for message in self.selected_message:
            req = message.getRequest()
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
                json_dict = json.loads(
                    bytes_to_string_esc_shift_jis(req[offset:]))
                params = get_json_params(json_dict)
                for key in params.keys():
                    keys_in_json.append(key)
                keys_in_json.sort()
                keys += keys_in_json

            self.stdout.println(
                "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
            is_diff = False
            out = []
            for line in unified_diff(self.pre_keys, keys, fromfile='before', tofile='after', n=999):
                is_diff = True
                self.stdout.println(line)

            if not is_diff:
                self.stdout.println("No difference in param names")
            self.stdout.println("//////////////////////////////")
            self.pre_keys = keys

        return


def bytes_to_string_esc_shift_jis(_bytes):
    chr_array = []
    esc_flg = False
    for code in _bytes:
        code %= 0x100

        c = ""
        if esc_flg or (0x80 <= code and 0xa0 > code) or (0xe0 <= code):
            c = "\\x"+hex(code)[2:]
            esc_flg = not esc_flg
        elif 0x80 <= code:
            c = "\\x"+hex(code)[2:]
        else:
            c = chr(code)
            if c == "\\":
                c = "\\\\"
        chr_array.append(c)
    out = "".join(chr_array)

    return out.replace("\\", "\\\\")


def string_to_bytes_unesc_shift_jis(_str):
    bytes_array = []
    esc_count = 0
    backslash = False
    code = ""
    for c in _str:
        if backslash:
            if c == "\\":
                bytes_array.append(ord("\\"))
            elif c == "x":
                esc_count = 2
            backslash = False

        elif esc_count:
            code += c
            esc_count -= 1
            if not esc_count:
                bytes_array.append(uchar_to_char(int(code, 16)))
                code = ""

        else:
            if c == "\\":
                backslash = True
            else:
                bytes_array.append(uchar_to_char(ord(c)))

    return bytes_array


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


def uchar_to_char(c):
    if c >= 0x80:
        c -= 0x100
    return c
