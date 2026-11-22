/**
 * dsh-lan-peers · 测试端口助手（client / lib / host/test 三处共用）
 *
 * 为什么需要它：`listen(0)` 由操作系统随机发一个临时端口，而 undici/fetch 拒绝
 * WHATWG 的「bad port」列表（6000/X11、4190、6697/IRCS、10080/amanda 等）。
 * 一旦随机落到其中一个，同一条用例就变成「连不上 / bad port」的假红 ——
 * 这条坑在本仓库已经复现三次（6000、6697、4190）。
 *
 * 两种自证方式，按 server 种类分（这不是审美选择，是实测出来的）：
 *
 *   - 产品里的 peer server（createPeerServer：没有 address()，带 config/group）：
 *     静态表快筛 + **真打一次 http://host:port/v1/health**。这正是 host/test/helpers.mjs
 *     一直以来的做法，保持 1:1 —— 它顺带把 undici 的连接池预热了；实测去掉这步，
 *     group-commit 的三节点 quorum 用例会 2~5/5 飘红（第一笔 propose 的 fetch 冷启动
 *     吃掉 commitTimeoutMs 的大半，直接 503 quorum-unavailable）。
 *
 *   - 原生 http/net server（测试桩、黑洞服务器；有 address()）：
 *     **只查静态表，一次网络都不发**。实测这三种都更糟：真打 /v1/health 会给
 *     「数请求条数」的桩多记一笔（cli-* 35 条断言当场全红）；打 .invalid 也会在
 *     group-commit 里留下副作用（2~3/5 飘红，即使换成 race 定时器也一样）。
 *     HEAD 时代这些桩本来就不经过助手（裸 listen 在测试文件里），所以这条分支
 *     保持「不发网络请求」才是零语义变化的那一档。
 *
 * 铁律：任何 *.test.mjs 都不许再写裸 listen( 0 ) —— 由 host/test/ports-scan.test.mjs 静态拦截。
 */

/**
 * fetch（undici）拒绝的端口 —— WHATWG 的 bad port 列表。
 * 不是手抄的散文：它按 WHATWG 规范逐项列出（含 6679/4190 这类后来补的）。
 */
export const FETCH_BLOCKED_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95,
  101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179,
  389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601,
  636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061, 6000, 6566,
  4190, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
]);

export function isFetchBlockedPort(port) {
  return FETCH_BLOCKED_PORTS.has(Number(port));
}

/**
 * 这条端口能不能被 undici fetch？只关心 "bad port"，其它错误（连接拒绝、超时等）都算可用。
 * 为什么不用静态列表兜底：手抄 WHATWG 列表会漏项（实测漏过 6679、4190），
 * 一旦漏项就是"不明原因的飘红"。这里直接问一次 fetch，免疫列表漂移。
 *
 * 注意：调用方只对 peer server 用它（见文件头）。测试桩不要用 —— 它会给桩多记一笔请求。
 * 超时用 race 定时器而不是 AbortSignal.timeout：后者的定时器在 fetch 提前失败后仍然挂着，
 * 会在两秒后把无关的在途请求带崩（实测）。
 */
export async function fetchRejectsPort(host, port, options = {}) {
  const opts = typeof options === 'number' ? { timeoutMs: options } : (options || {});
  const timeoutMs = opts.timeoutMs || 2000;
  const raw = opts.target === 'port-only'
    ? 'http://port-probe.invalid:' + port + '/v1/health'
    : 'http://' + host + ':' + port + '/v1/health';
  let timer = null;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve('timeout'), timeoutMs);
    if (timer && typeof timer.unref === 'function') timer.unref();
  });
  try {
    const outcome = await Promise.race([fetch(raw).then(() => 'ok', (error) => error), timeout]);
    if (outcome === 'timeout' || outcome === 'ok') return false;
    const text = String(outcome?.cause?.message ?? outcome?.message ?? outcome);
    return /bad port/i.test(text);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * 这颗 server 要不要发网络自证：只有产品里的 peer server 要（见文件头）。
 * 原生 server 一定有 address()；createPeerServer 没有。
 */
function needsLiveProbe(server) {
  return typeof server?.address !== 'function';
}

function addressPortOf(server) {
  const address = typeof server.address === 'function' ? server.address() : null;
  return address && typeof address === 'object' ? Number(address.port) : 0;
}

/**
 * 让 server 监听一个随机端口并返回 { port, url }（自定义 server 则原样返回它的 info）。
 * Node 原生 server 的 listen() 返回自身（非 thenable），这里补等 'listening' 事件。
 */
async function startListening(server, host, requested = 0) {
  const started = server.listen(requested, host);
  if (started && typeof started.then === 'function') {
    const info = await started;
    if (info && typeof info === 'object' && Number(info.port) > 0) return info;
    const port = addressPortOf(server);
    return { port, url: 'http://' + host + ':' + port };
  }
  if (server.listening !== true) {
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        server.removeListener('listening', onListening);
        reject(error);
      };
      const onListening = () => {
        server.removeListener('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
    });
  }
  const port = addressPortOf(server);
  return { port, url: 'http://' + host + ':' + port };
}

/** 关掉刚起的那个监听（只为「这个端口被 fetch 拒了，换一个」这条路径服务）。 */
async function stopListening(server) {
  if (typeof server.close !== 'function') return;
  await new Promise((resolve) => {
    let settled = false;
    const finish = () => { if (settled) return; settled = true; resolve(); };
    try {
      const out = server.close(finish);
      if (out && typeof out.then === 'function') out.then(finish, finish);
      // 少数 server 的 close 既不接回调也不发 'close'：兜底，别把测试挂死。
      const timer = setTimeout(finish, 2000);
      if (timer && typeof timer.unref === 'function') timer.unref();
    } catch {
      finish();
    }
  });
}

// 显式候选端口的扫描区间：RFC 6335 的动态/私有端口段（49152-65535）。
// 选它而不是操作系统 ip_local_port_range，是因为这段在所有平台上都合法可用，
// 且不会与内核正在发放的临时端口撞车（那正是下面要绕开的来源）。
const CANDIDATE_PORT_MIN = 49152;
const CANDIDATE_PORT_MAX = 65535;

/**
 * 在扫描区间里挑一个「没被 fetch 拒过、这一发还没问过」的端口：
 * 随机起点 + 线性扫描，整段最多走一圈（有界），走空返回 0。
 * 随机起点是为了并发跑的多条用例不会从同一个号开始抢。
 */
function pickCandidatePort(asked) {
  const span = CANDIDATE_PORT_MAX - CANDIDATE_PORT_MIN + 1;
  const start = Math.floor(Math.random() * span);
  for (let step = 0; step < span; step += 1) {
    const candidate = CANDIDATE_PORT_MIN + ((start + step) % span);
    if (isFetchBlockedPort(candidate) || asked.has(candidate)) continue;
    return candidate;
  }
  return 0;
}

/**
 * listen( 0 ) + 避开 fetch 黑名单端口，撞上就换一个（最多 attempts 个不同端口）。
 *
 * 为什么不能只是「关掉再 listen(0)」：Linux/Windows 的内核会把刚释放的临时端口
 * 优先再发一次，于是每次重试都可能落回同一个 bad port，循环耗尽 —— 这就是
 * "no fetch-safe ephemeral port after 5 attempts (last=6669)" 那条假红。
 * 所以第 1 发仍走 listen(0)（happy path 一次命中，行为与旧实现逐字相同），
 * 之后每一发改成**显式**端口，且跳过本调用里已经问过 / 已经被 fetch 拒掉的号。
 *
 * 用法：const info = await listenOnRandomPort(server);  // info.port / info.url
 */
export async function listenOnRandomPort(server, host = '127.0.0.1', attempts = 5) {
  const live = needsLiveProbe(server);
  const asked = new Set();          // 本调用问过的端口：保证每一次都是新的
  let last = null;
  const budget = Math.max(1, Number(attempts) || 0);
  for (let index = 0; index < budget; index += 1) {
    const requested = index === 0 ? 0 : pickCandidatePort(asked);
    if (index > 0 && requested === 0) break;  // 候选段已经扫空
    asked.add(requested);
    let info = null;
    try {
      info = await startListening(server, host, requested);
    } catch (error) {
      if (index === 0) throw error;   // listen(0) 的失败照旧上抛：调用方看到的东西不变
      last = requested;               // 显式候选被占用：记下，换下一个
      continue;
    }
    const safeByList = !isFetchBlockedPort(info.port);
    if (safeByList && (!live || !(await fetchRejectsPort(host, info.port, { target: 'server' })))) return info;
    last = info.port;
    await stopListening(server);
  }
  const tried = [...asked];
  throw new Error('no fetch-safe port after ' + tried.length + ' distinct ports tried'
    + ' (' + tried.join(', ') + '; last=' + last + ')');
}
