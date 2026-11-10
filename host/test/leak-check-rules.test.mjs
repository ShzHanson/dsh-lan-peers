/**
 * scripts/leak-check.mjs 内置规则的回归测试。
 *
 * 为什么字面量全部拼出来：这些地址与路径正是规则要抓的东西，
 * 直接写进一个被跟踪文件会让检查器把自己报成泄漏。所以统一用 ip()/drive() 构造，
 * 源码里（包括测试标题和注释）不出现任何真实形态的地址或盘符路径。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { SECRET_RULES } from '../../scripts/leak-check.mjs';

const BS = '\\';
const ip = (...octets) => octets.join('.');
const drive = (letter, ...segs) => letter + ':' + segs.map((seg) => BS + seg).join('');
// JS 源码里的双反斜杠形态（'C:\\Windows\\…'）
const escaped = (value) => value.replaceAll(BS, BS + BS);

function ruleByName(name) {
  const found = SECRET_RULES.find((rule) => rule.name === name);
  assert.ok(found, '规则应存在：' + name);
  return found;
}

// 复刻 scanText 的判定顺序：先正则命中，再走 ignore。
function caught(name, text) {
  const rule = ruleByName(name);
  const match = rule.re.exec(text);
  rule.re.lastIndex = 0;
  if (!match) return false;
  return !(typeof rule.ignore === 'function' && rule.ignore(match, 'fixture.mjs'));
}

test('internal-ipv4：放行按精确值，不按网段', () => {
  // 这四条是关键断言：允许表里没有写到的地址必须照报——尤其是真正泄漏过的那个网段，
  // 以及两个最常见家用网段里的其它主机。
  assert.equal(caught('internal-ipv4', ip(192, 168, 5, 51)), true, '泄漏过的网段必须命中');
  assert.equal(caught('internal-ipv4', ip(10, 0, 0, 51)), true, '10.0.0.0/24 里未放行的主机必须命中');
  assert.equal(caught('internal-ipv4', ip(192, 168, 0, 10)), true, '192.168.0.0/24 里未放行的主机必须命中');
  assert.equal(caught('internal-ipv4', ip(10, 1, 2, 99)), true, '10.1.2.3 同网段的其它主机必须命中');

  assert.equal(caught('internal-ipv4', ip(172, 20, 3, 4)), true, '172.16/12 里的新主机必须命中');
  // 允许表里的精确值反向确认：放行是逐值生效的
  assert.equal(caught('internal-ipv4', ip(10, 1, 2, 3)), false, '允许表里的精确值放行');
  assert.equal(caught('internal-ipv4', ip(10, 0, 0, 2)), false, '允许表里的精确值放行');
});

test('internal-ipv4：网段定义与文档地址段不命中', () => {
  assert.equal(caught('internal-ipv4', ip(192, 168, 1, 10) + ':7788'), false, '文档占位网段放行');
  assert.equal(caught('internal-ipv4', ip(192, 168, 1, 0) + '/24'), false);
  assert.equal(caught('internal-ipv4', ip(10, 0, 0, 0) + '/8'), false, 'CIDR 网段定义不命中');
  assert.equal(caught('internal-ipv4', ip(172, 16, 0, 0) + '/12'), false, 'CIDR 网段定义不命中');
  assert.equal(caught('internal-ipv4', ip(127, 0, 0, 1)), false, '回环不命中');
  assert.equal(caught('internal-ipv4', ip(0, 0, 0, 0)), false, '通配地址不命中');
  assert.equal(caught('internal-ipv4', ip(203, 0, 113, 7)), false, 'TEST-NET-3 不命中');
  assert.equal(caught('internal-ipv4', ip(198, 51, 100, 4)), false, 'TEST-NET-2 不命中');
  assert.equal(caught('internal-ipv4', ip(192, 0, 2, 9)), false, 'TEST-NET-1 不命中');
  assert.equal(caught('internal-ipv4', 'localhost:7788'), false, 'localhost 不命中');
});

test('workstation-path：只放行系统目录与文档示例前缀', () => {
  assert.equal(caught('workstation-path', drive('D', 'DS-Harness')), true, '盘符工作区必须命中');
  assert.equal(caught('workstation-path', drive('C', 'Users', 'user')), true, '用户目录必须命中');
  assert.equal(caught('workstation-path', drive('D', 'MyWork', 'proj')), true);
  assert.equal(caught('workstation-path', drive('E', 'projects', 'app')), true);
  // 双反斜杠形态同样要能命中，证明 \\{1,2} 的容错不是单向的
  assert.equal(caught('workstation-path', escaped(drive('D', 'DS-Harness'))), true, 'JS 转义形态也要命中');

  assert.equal(caught('workstation-path', drive('C', 'Windows', 'System32')), false, '系统目录放行');
  assert.equal(caught('workstation-path', escaped(drive('C', 'Windows', 'System32'))), false, '转义后的系统目录放行');
  assert.equal(caught('workstation-path', drive('C', 'tmp', 'x.exe')), false, '清洗函数文档示例放行');
  assert.equal(caught('workstation-path', drive('D', 'secret', 'ws')), false, '路径清洗夹具放行');
  assert.equal(caught('workstation-path', drive('D', '/work')), false, '正则字面量产物放行');
  assert.equal(caught('workstation-path', 'http://example.com/x'), false, 'URL 不命中');
  assert.equal(caught('workstation-path', 'https://' + ip(127, 0, 0, 1) + ':7788'), false, 'URL 不命中');
});

test('workstation-path：普通代码行不命中', () => {
  const code = "const baseUrl = 'http://' + peerHost + ':' + port + '/v1/health';";
  assert.equal(caught('workstation-path', code), false);
  assert.equal(caught('internal-ipv4', code), false);
});

// 非空验证一：若把「逐值放行」换成「按网段放行」，下面第一条断言就会变红。
test('非空验证：网段放行会漏掉同网段里的其它主机', () => {
  const subnetStyle = (value) => value.startsWith('10.0.0.');
  assert.equal(subnetStyle(ip(10, 0, 0, 51)), true, '网段式放行确实会把这个主机一起放掉');
  assert.equal(caught('internal-ipv4', ip(10, 0, 0, 51)), true, '真实规则必须照报——这就是非空验证');
});

// 非空验证二：若去掉外圈的后顾断言，朴素写法会把 URL 误判成盘符路径。
test('非空验证：去掉后顾断言就会把 URL 误判成路径', () => {
  const naive = /[A-Za-z]:\\/;
  assert.equal(naive.test(drive('D', 'DS-Harness')), true, '朴素写法能命中真路径');
  assert.equal(caught('workstation-path', 'http://example.com/x'), false, '真实规则挡住 URL');
  assert.equal(caught('workstation-path', drive('D', 'DS-Harness')), true, '真实规则仍命中真路径');
});
