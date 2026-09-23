<?php
/**
 * 字速挑战 · 成绩接口（PHP，JSONL 逐行文件存储，无需数据库）
 * 兼容 PHP 5.4+ 与 7.x/8.x（不使用 PHP 7 语法）
 *
 * 高并发设计：
 *   提交成绩 = O(1) 追加一行（FILE_APPEND + LOCK_EX，锁持有时间极短）
 *   读取/汇总 = 共享锁（LOCK_SH）并发读，互不阻塞
 *
 * 部署：与 index.html 放在同一目录，PHP 需对网站目录有写权限（接口会自动创建 data/ 目录）。
 * 动作：
 *   POST api.php?action=login （JSON: password, id）     校验访问密码，签发成绩签名令牌（绑定学号，限时）
 *   GET  api.php?action=summary&id=学号&lang=zh|en     个人最佳 + 最近 5 条记录
 *   POST api.php?action=submit （JSON 成绩数据+令牌）   验签通过才保存，返回最新汇总
 *   GET  api.php?action=list&key=管理密钥 [&format=csv]  导出全部成绩（部署前先修改 ADMIN_KEY）
 * 防护：URL ≤ 2KB、POST 包体 ≤ 4KB、仅允许 GET/POST；字段一律截断+数值限幅。
 */

date_default_timezone_set('Asia/Shanghai');

const ADMIN_KEY   = 'CHANGE_ME';        // ← 导出成绩用的管理密钥，部署前务必改成自己的随机字符串
const APP_KEY     = 'CHANGE_ME_PWD';    // ← 现场访问密码（登记页输入），部署前务必修改并现场公布，不要写进网页源码
const APP_SECRET  = 'CHANGE_ME_SECRET'; // ← 成绩签名密钥，部署前务必改成自己的随机字符串
const TOKEN_TTL   = 28800;              // 登录令牌有效期（秒），默认 8 小时，覆盖一整场活动
const DATA_DIR    = __DIR__ . '/data';
const DATA_FILE   = DATA_DIR . '/scores.jsonl';
const LEGACY_FILE = DATA_DIR . '/scores.json'; // 旧版数组格式，遇到会自动迁移

// PHP < 5.6 没有 hash_equals，这里补一个恒定时间比较
if (!function_exists('hash_equals')) {
  function hash_equals($known, $user) {
    if (!is_string($known) || !is_string($user) || strlen($known) !== strlen($user)) return false;
    $result = 0;
    for ($i = 0; $i < strlen($known); $i++) $result |= ord($known[$i]) ^ ord($user[$i]);
    return $result === 0;
  }
}

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('X-Content-Type-Options: nosniff');
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '';
if ($method === 'OPTIONS') {
  header('Access-Control-Allow-Headers: Content-Type');
  header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
  http_response_code(204);
  exit;
}

// —— 网络防护：限制请求方法与大小，防止恶意超大请求耗尽内存/带宽 ——
const MAX_URI_LENGTH = 2048; // URL + 查询串上限
const MAX_BODY_SIZE  = 4096; // POST 包体上限（正常一条成绩 JSON 约 300 字节，4KB 余量充足）

if (strlen((string)(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '')) > MAX_URI_LENGTH) {
  fail('请求 URI 过长。', 414);
}
if ($method !== 'GET' && $method !== 'POST') {
  header('Allow: GET, POST');
  fail('不支持的请求方法。', 405);
}
$body = '';
if ($method === 'POST') {
  // 先看 Content-Length 声明值，再按上限+1 硬截断读取（双保险，绝不把超大包读进内存）
  if (isset($_SERVER['CONTENT_LENGTH']) && (int)$_SERVER['CONTENT_LENGTH'] > MAX_BODY_SIZE) fail('请求数据过大。', 413);
  $body = (string)file_get_contents('php://input', false, null, 0, MAX_BODY_SIZE + 1);
  if (strlen($body) > MAX_BODY_SIZE) fail('请求数据过大。', 413);
}

function respond($data, $code = 200) {
  http_response_code($code);
  echo json_encode($data, JSON_UNESCAPED_UNICODE);
  exit;
}

function fail($message, $code = 400) {
  respond(array('ok' => false, 'error' => $message), $code);
}

function text($value, $max) {
  $value = trim((string)$value);
  $value = preg_replace('/[\x00-\x1F\x7F]/u', '', $value);
  if ($value === null) return ''; // 非法 UTF-8 输入直接丢弃
  preg_match('/^.{0,' . (int)$max . '}/us', $value, $matches); // 按字符安全截断，兼容中文
  return isset($matches[0]) ? $matches[0] : '';
}

function clamp($value, $min, $max) {
  return max($min, min($max, (int)round((float)$value)));
}

function clampf($value, $min, $max) {
  return max($min, min($max, (float)$value));
}

/** 成绩签名令牌：HMAC-SHA256(学号|过期时间, APP_SECRET)，绑定学号且限时有效 */
function make_token($id, $exp) {
  return hash_hmac('sha256', $id . '|' . $exp, APP_SECRET);
}

/** 读取全部成绩（共享锁，允许并发读）；首次遇到旧版 scores.json 时自动迁移为逐行格式 */
function loadAll() {
  if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0755, true)) fail('服务器无法创建数据目录。', 500);
  // Apache 屏蔽数据目录防止直接下载；nginx 需在配置里 deny 掉 /data/
  if (!is_file(DATA_DIR . '/.htaccess')) @file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\n");
  if (!is_file(DATA_FILE) && is_file(LEGACY_FILE)) {
    $legacy = json_decode((string)file_get_contents(LEGACY_FILE), true);
    if (is_array($legacy)) {
      $lines = '';
      foreach ($legacy as $r) {
        if (is_array($r)) $lines .= json_encode($r, JSON_UNESCAPED_UNICODE) . "\n";
      }
      if ($lines !== '') file_put_contents(DATA_FILE, $lines, LOCK_EX);
    }
  }
  if (!is_file(DATA_FILE)) return array();
  $handle = @fopen(DATA_FILE, 'r');
  if (!$handle) fail('服务器无法打开数据文件。', 500);
  flock($handle, LOCK_SH); // 共享锁：多个查询并发读不互斥
  $raw = stream_get_contents($handle);
  flock($handle, LOCK_UN);
  fclose($handle);
  $scores = array();
  foreach (explode("\n", (string)$raw) as $line) {
    $line = trim($line);
    if ($line === '') continue;
    $record = json_decode($line, true);
    if (is_array($record)) $scores[] = $record;
  }
  return $scores;
}

function summaryOf($scores, $id, $lang) {
  $mine = array();
  foreach ($scores as $record) {
    $rid = isset($record['id']) ? $record['id'] : '';
    $rlang = isset($record['language']) ? $record['language'] : '';
    if ($rid === $id && $rlang === $lang) $mine[] = $record;
  }
  $best = 0;
  foreach ($mine as $record) $best = max($best, (int)(isset($record['score']) ? $record['score'] : 0));
  $history = array_slice(array_reverse($mine), 0, 5);
  return array(
    'best' => $best,
    'history' => array_map(function ($r) {
      return array(
        'date' => (string)(isset($r['date']) ? $r['date'] : ''),
        'score' => (int)(isset($r['score']) ? $r['score'] : 0),
        'speed' => (int)(isset($r['speed']) ? $r['speed'] : 0),
        'accuracy' => (int)(isset($r['accuracy']) ? $r['accuracy'] : 0),
        'completion' => (int)(isset($r['completion']) ? $r['completion'] : 0),
        'seconds' => (string)(isset($r['seconds']) ? $r['seconds'] : '0.0'),
      );
    }, $history),
  );
}

$action = isset($_GET['action']) ? $_GET['action'] : '';

if ($action === 'login') {
  if ($method !== 'POST') fail('请使用 POST 登录。', 405);
  $input = json_decode($body, true);
  if (!is_array($input)) fail('登录数据格式错误。');
  $password = text(isset($input['password']) ? $input['password'] : '', 64);
  $id = text(isset($input['id']) ? $input['id'] : '', 32);
  if ($id === '') fail('缺少学号。');
  if (APP_KEY === '' || !hash_equals(APP_KEY, $password)) fail('访问密码不正确。', 401);
  $exp = time() + TOKEN_TTL;
  respond(array('ok' => true, 'token' => make_token($id, $exp), 'exp' => $exp));
}

if ($action === 'summary') {
  $id = text(isset($_GET['id']) ? $_GET['id'] : '', 32);
  $lang = (isset($_GET['lang']) ? $_GET['lang'] : '') === 'en' ? 'en' : 'zh';
  if ($id === '') fail('缺少学号。');
  $summary = summaryOf(loadAll(), $id, $lang);
  respond(array_merge(array('ok' => true), $summary));
}

if ($action === 'submit') {
  if ($method !== 'POST') fail('请使用 POST 提交成绩。', 405);
  $input = json_decode($body, true); // $body 已在上方按大小限制安全读取
  if (!is_array($input)) fail('成绩数据格式错误。');
  $get = function ($key, $default = '') use ($input) { return isset($input[$key]) ? $input[$key] : $default; };
  $record = array(
    'id'          => text($get('id'), 32),
    'name'        => text($get('name'), 40),
    'college'     => text($get('college'), 80),
    'major'       => text($get('major'), 80),
    'language'    => $get('language') === 'en' ? 'en' : 'zh',
    'round'       => clamp($get('round', 1), 1, 999),
    'score'       => clamp($get('score', 0), 0, 100),
    'speed'       => clamp($get('speed', 0), 0, 999),
    'accuracy'    => clamp($get('accuracy', 0), 0, 100),
    'completion'  => clamp($get('completion', 0), 0, 100),
    'seconds'     => number_format(clampf($get('seconds', 0), 0, 86400), 1, '.', ''),
    'date'        => text($get('date'), 20),
    'ts'          => date('Y-m-d H:i:s'),
    'ip'          => (string)(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ''),
    'uid'         => text($get('uid'), 64),
  );
  if ($record['id'] === '' || $record['name'] === '') fail('缺少学号或姓名。');
  // 登录令牌校验：进场时由 action=login 签发，绑定学号 + 有效期，防止知道接口地址就伪造成绩
  $token = isset($input['token']) ? text($input['token'], 80) : '';
  $exp = isset($input['exp']) ? (int)$input['exp'] : 0;
  if ($exp < time() || !hash_equals(make_token($record['id'], $exp), $token)) {
    fail('成绩签名无效或已过期，请重新登记进场。', 401);
  }
  $scores = loadAll();
  // 幂等保护：网络重试时，最近 20 条里已有相同 uid 就不再重复写入
  $duplicate = false;
  if ($record['uid'] !== '') {
    foreach (array_slice($scores, -20) as $recent) {
      if ((isset($recent['uid']) ? $recent['uid'] : '') === $record['uid']) { $duplicate = true; break; }
    }
  }
  if (!$duplicate) {
    $line = json_encode($record, JSON_UNESCAPED_UNICODE);
    if ($line === false) fail('成绩数据编码失败。', 500);
    if (@file_put_contents(DATA_FILE, $line . "\n", FILE_APPEND | LOCK_EX) === false) fail('服务器无法写入成绩文件。', 500);
    $scores[] = $record;
  }
  $summary = summaryOf($scores, $record['id'], $record['language']);
  respond(array_merge(array('ok' => true), $summary));
}

if ($action === 'list') {
  $key = isset($_GET['key']) ? $_GET['key'] : '';
  if (!hash_equals(ADMIN_KEY, (string)$key)) fail('管理密钥不正确。', 403);
  $scores = loadAll();
  if ((isset($_GET['format']) ? $_GET['format'] : '') === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="scores-' . date('Ymd-His') . '.csv"');
    echo "\xEF\xBB\xBF"; // 带 BOM，Excel 直接打开不乱码
    $out = fopen('php://output', 'w');
    fputcsv($out, array('提交时间', '学号', '姓名', '学院', '专业', '语言', '轮次', '综合分', '速度', '准确率%', '完成度%', '用时(秒)', '提交IP'));
    foreach ($scores as $r) {
      fputcsv($out, array(
        isset($r['ts']) ? $r['ts'] : '',
        isset($r['id']) ? $r['id'] : '',
        isset($r['name']) ? $r['name'] : '',
        isset($r['college']) ? $r['college'] : '',
        isset($r['major']) ? $r['major'] : '',
        isset($r['language']) ? $r['language'] : '',
        isset($r['round']) ? $r['round'] : '',
        isset($r['score']) ? $r['score'] : '',
        isset($r['speed']) ? $r['speed'] : '',
        isset($r['accuracy']) ? $r['accuracy'] : '',
        isset($r['completion']) ? $r['completion'] : '',
        isset($r['seconds']) ? $r['seconds'] : '',
        isset($r['ip']) ? $r['ip'] : '',
      ));
    }
    exit;
  }
  respond(array('ok' => true, 'total' => count($scores), 'scores' => $scores));
}

fail('未知操作。', 404);
