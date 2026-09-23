# -*- coding: utf-8 -*-
"""
限速验证脚本：对自己部署的成绩接口高频并发请求，验证 mod_evasive 是否生效。
仅用于测试自己的服务器。

用法：
  python rate_limit_test.py http://103.59.145.197/gxnu/
  python rate_limit_test.py http://103.59.145.197/gxnu/ --count 500 --threads 20

说明：默认 10 线程 + keep-alive 连接复用，跨境链路也能打到限速阈值。
预期：开头返回 200，触发阈值后变 403；封禁 60 秒后自动恢复。
"""

import argparse
import http.client
import ssl
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

_lock = threading.Lock()
_codes = Counter()
_first_block = {'n': None}


class Client:
    """keep-alive 连接复用（模拟浏览器：一条连接发多个请求）"""

    def __init__(self, base, timeout=10, insecure=False):
        u = urllib.parse.urlsplit(base)
        self.scheme = u.scheme or 'http'
        self.host = u.hostname
        self.port = u.port or (443 if self.scheme == 'https' else 80)
        self.path_base = u.path.rstrip('/')
        self.timeout = timeout
        self.insecure = insecure
        self.conn = None

    def _connect(self):
        if self.scheme == 'https':
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(self, path):
        if self.conn is None:
            self._connect()
        try:
            self.conn.request('GET', self.path_base + path)
            resp = self.conn.getresponse()
            resp.read()
            return resp.status, None
        except Exception as e:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None
            return 0, type(e).__name__


_sent = {'n': 0}


def run(client, path, total):
    while True:
        with _lock:
            if _sent['n'] >= total:
                return
            _sent['n'] += 1
            n = _sent['n']
        status, err = client.request(path)
        code = err if err else str(status)
        with _lock:
            _codes[code] += 1
            if code == '403' and _first_block['n'] is None:
                _first_block['n'] = n
                print('>> 第 %d 个请求触发 403，限速生效' % n)
            if n % 50 == 0:
                print('  已发送 %d/%d' % (n, total))


def main():
    parser = argparse.ArgumentParser(description='验证接口限速（mod_evasive）')
    parser.add_argument('base', help='例如 http://103.59.145.197/gxnu/')
    parser.add_argument('--count', type=int, default=300, help='总请求数（默认 300）')
    parser.add_argument('--threads', type=int, default=10, help='并发线程数（默认 10）')
    parser.add_argument('--insecure', action='store_true', help='跳过 HTTPS 证书校验')
    args = parser.parse_args()

    path = '/api.php?action=summary&id=ratelimit&lang=zh'
    print('目标：%s%s' % (args.base.rstrip('/'), path))
    print('%d 线程并发发送 %d 个请求（连接复用开启）...\n' % (args.threads, args.count))

    start = time.time()
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for _ in range(args.threads):
            pool.submit(run, Client(args.base, insecure=args.insecure), path, args.count)

    print('\n========== 验证报告 ==========')
    print('总请求：%d，耗时 %.1f 秒' % (args.count, time.time() - start))
    for code, n in _codes.most_common():
        print('  %-12s x %d' % (code, n))
    if _first_block['n']:
        print('结论：限速在第 %d 个请求时触发，mod_evasive 工作正常' % _first_block['n'])
    elif '403' not in _codes:
        print('结论：未触发限速——检查 mod_evasive 是否加载（httpd -M | grep evasive）或阈值是否过高')
    print('==============================')


if __name__ == '__main__':
    main()
