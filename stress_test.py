#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
字速挑战 · 接口压力测试脚本（仅用 Python 标准库，无需 pip 安装）

模拟大量参与者同时「进场查询成绩 + 交卷提交」，输出成功率、吞吐、延迟分布。
提交的成绩 id 统一以 STRESS 开头，压测后便于清理。

用法示例：
  python stress_test.py http://127.0.0.1:8000
  python stress_test.py http://服务器IP --users 200 --concurrency 100 --rounds 5
  python stress_test.py https://你的域名 --users 100 --key 你的管理密钥   # 附带数据完整性校验
  python stress_test.py https://你的域名 --insecure                      # 自签名证书时跳过校验

注意：
  1. php -S 内置服务器默认单进程，压测前建议多开 worker（Linux）：
     PHP_CLI_SERVER_WORKERS=16 php -S 0.0.0.0:8000
     否则测出的是「单进程排队」，不代表 nginx + php-fpm 的真实性能。
  2. 压测数据清理（服务器上）：
     grep -v '"id":"STRESS' data/scores.jsonl > tmp && mv tmp data/scores.jsonl
"""

import argparse
import http.client
import json
import random
import ssl
import threading
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

COLLEGES = ['计算机学院', '数学与统计学院', '物理科学与技术学院', '电子工程学院']
MAJORS = ['软件工程', '计算机科学与技术', '数据科学与大数据技术', '通信工程', '人工智能']

_lock = threading.Lock()
_stats = {'success': 0, 'fail': 0, 'submits': 0, 'errors': {}, 'latencies': []}
_stop = False


class Client:
    """带 keep-alive 连接复用的 HTTP 客户端（模拟浏览器行为：一条连接发多个请求）"""

    def __init__(self, base, timeout=10, insecure=False):
        u = urlsplit(base)
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

    def request(self, method, path, payload=None):
        if self.conn is None:
            self._connect()
        body = json.dumps(payload).encode('utf-8') if payload is not None else None
        headers = {'Content-Type': 'application/json'} if body is not None else {}
        start = time.perf_counter()
        try:
            self.conn.request(method, self.path_base + path, body=body, headers=headers)
            resp = self.conn.getresponse()
            data = resp.read()
            return resp.status, data, time.perf_counter() - start, None
        except Exception as e:  # 超时/断连：丢弃这条连接，下次重连
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None
            return 0, b'', time.perf_counter() - start, type(e).__name__


def record(ok, latency, error=None):
    with _lock:
        if ok:
            _stats['success'] += 1
        else:
            _stats['fail'] += 1
            key = error or 'unknown'
            _stats['errors'][key] = _stats['errors'].get(key, 0) + 1
        _stats['latencies'].append(latency)


def ok_response(body):
    """解析响应 JSON 并判断 ok 字段（不依赖空格/序列化格式）"""
    try:
        return bool(json.loads(body.decode('utf-8')).get('ok'))
    except Exception:
        return False


def classify(status, err):
    """错误分类：网络异常用异常名；HTTP 层失败用状态码（如 HTTP 403 = 被 mod_evasive 限速）"""
    if err:
        return err
    if status != 200:
        return 'HTTP %s' % status
    return None


def worker(client, user_index, rounds, lang):
    sid = 'STRESS%05d' % user_index
    for r in range(1, rounds + 1):
        if _stop:
            return
        # 1) 进场：查询个人最佳/历史（对应页面解锁后的 syncFromServer）
        status, body, latency, err = client.request(
            'GET', '/api.php?action=summary&id=' + sid + '&lang=' + lang)
        record(status == 200 and ok_response(body), latency, classify(status, err))

        # 2) 交卷：提交一条随机成绩（对应页面结束挑战后的 uploadScore）
        payload = {
            'id': sid,
            'name': '压测%03d' % user_index,
            'college': random.choice(COLLEGES),
            'major': random.choice(MAJORS),
            'language': lang,
            'round': r,
            'score': random.randint(0, 100),
            'speed': random.randint(0, 150),
            'accuracy': random.randint(50, 100),
            'completion': random.choice([100, 100, 100, 87, 64]),
            'seconds': round(random.uniform(30, 180), 1),
            'date': time.strftime('%Y/%m/%d'),
            'savedAt': time.strftime('%Y-%m-%dT%H:%M:%S+08:00'),
            'uid': sid + '-r%d-%s' % (r, uuid.uuid4().hex[:8]),
        }
        status, body, latency, err = client.request(
            'POST', '/api.php?action=submit', payload)
        ok = status == 200 and ok_response(body)
        with _lock:
            if ok:
                _stats['submits'] += 1
        record(ok, latency, classify(status, err))


def get_total(client, key):
    status, body, _, _ = client.request(
        'GET', '/api.php?action=list&key=' + urllib.parse.quote(key))
    if status != 200:
        return None
    try:
        return json.loads(body.decode('utf-8')).get('total')
    except Exception:
        return None


def check_integrity(client, key, users, rounds):
    """校验：压测写入的总数正确，且 uid 无重复（幂等去重生效）"""
    status, body, _, _ = client.request('GET', '/api.php?action=list&key=' + urllib.parse.quote(key))
    if status != 200:
        print('[校验] 无法读取全部成绩（检查 key 是否正确）')
        return
    data = json.loads(body.decode('utf-8'))
    scores = data.get('scores', [])
    stress = [s for s in scores if str(s.get('id', '')).startswith('STRESS')]
    uids = [s.get('uid') for s in stress if s.get('uid')]
    dup = len(uids) - len(set(uids))
    print('[校验] STRESS 记录数（含历史压测）：%d（本次期望新增 %d，以「记录增量」为准）' % (len(stress), users * rounds))
    print('[校验] 重复 uid：%d %s' % (dup, '，去重正常' if dup == 0 else '，出现重复！'))


def pct(values, p):
    if not values:
        return 0.0
    values = sorted(values)
    idx = min(len(values) - 1, max(0, int(round(len(values) * p / 100.0)) - 1))
    return values[idx]


def main():
    parser = argparse.ArgumentParser(description='字速挑战接口压力测试')
    parser.add_argument('base', help='例如 http://127.0.0.1:8000 或 https://你的域名')
    parser.add_argument('--users', type=int, default=100, help='虚拟参与者总数（默认 100）')
    parser.add_argument('--concurrency', type=int, default=50, help='并发线程数（默认 50）')
    parser.add_argument('--rounds', type=int, default=5, help='每人挑战次数（默认 5）')
    parser.add_argument('--lang', default='zh', choices=['zh', 'en'])
    parser.add_argument('--timeout', type=int, default=10, help='单请求超时秒数（默认 10）')
    parser.add_argument('--key', default='', help='管理密钥，提供则附带数据完整性校验')
    parser.add_argument('--insecure', action='store_true', help='跳过 HTTPS 证书校验')
    args = parser.parse_args()

    base = args.base.rstrip('/')
    total = args.users * args.rounds * 2  # 每人每轮 = 1 查询 + 1 提交
    print('目标：%s | 参与者 %d 人 x %d 轮 | 并发 %d | 总请求 %d | 连接复用：开启' %
          (base, args.users, args.rounds, args.concurrency, total))
    admin_client = Client(args.base, timeout=15, insecure=args.insecure)
    if args.key:
        before = get_total(admin_client, args.key)
        print('压测前服务器总记录数：%s' % before)

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(worker, Client(args.base, timeout=args.timeout, insecure=args.insecure),
                               i, args.rounds, args.lang)
                   for i in range(1, args.users + 1)]
        done = 0
        for f in futures:
            f.result()
            done += 1
            if done % 20 == 0:
                print('  已完成 %d/%d 人...' % (done, args.users))
    elapsed = time.perf_counter() - start

    lat = _stats['latencies']
    print('\n========== 压测报告 ==========')
    print('总耗时     ：%.2f s' % elapsed)
    print('成功 / 失败：%d / %d（成功率 %.1f%%）' %
          (_stats['success'], _stats['fail'], 100.0 * _stats['success'] / max(1, _stats['success'] + _stats['fail'])))
    print('提交成功   ：%d 条成绩' % _stats['submits'])
    print('吞吐量     ：%.1f 请求/秒' % (len(lat) / max(1e-9, elapsed)))
    if lat:
        print('延迟平均   ：%d ms' % (sum(lat) / len(lat) * 1000))
        print('延迟 P50   ：%d ms' % (pct(lat, 50) * 1000))
        print('延迟 P95   ：%d ms' % (pct(lat, 95) * 1000))
        print('延迟最大   ：%d ms' % (max(lat) * 1000))
    if _stats['errors']:
        print('错误分布   ：')
        for k, v in sorted(_stats['errors'].items(), key=lambda kv: -kv[1]):
            print('  %-20s x %d' % (k, v))
    if args.key:
        after = get_total(admin_client, args.key)
        if before is not None and after is not None:
            print('记录增量   ：%d（期望 %d）' % (after - before, _stats['submits']))
        check_integrity(admin_client, args.key, args.users, args.rounds)
    print('==============================')
    print('清理压测数据（服务器上执行）：')
    print('  grep -v \'"id":"STRESS\' data/scores.jsonl > data/tmp.jsonl && mv data/tmp.jsonl data/scores.jsonl')


if __name__ == '__main__':
    main()
