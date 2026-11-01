// dsh-lan-peers · browser/desktop client half.
//
// Loaded through the app's client module loader (works for both the HTTP web UI
// and the Electron window, which runs on the `dsh-app://` scheme). Renders a
// floating "伙伴" button with the three admin actions; every call goes to the
// host routes under /api/lan-peers/*.
window.__ModuleLoader__.load({
  id: 'dsh-lan-peers',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useCallback, useEffect, useRef, useState } = React;

    // Floating launcher: draggable and remembers where you left it. The default
    // is the bottom-right corner so it never covers the app's own settings entry.
    const POS_KEY = 'dsh-lan-peers:launcher:v1';
    const EDGE = 8;
    const clampTo = (v, lo, hi) => Math.min(Math.max(v, lo), Math.max(lo, hi));
    const readPos = () => {
      try {
        const saved = JSON.parse(window.localStorage.getItem(POS_KEY) || 'null');
        if (saved && typeof saved.x === 'number' && typeof saved.y === 'number') return saved;
      } catch {}
      return null;
    };
    const writePos = (p) => { try { window.localStorage.setItem(POS_KEY, JSON.stringify(p)); } catch {} };
    const fitPos = (x, y, w, h) => ({
      x: clampTo(x, EDGE, window.innerWidth - w - EDGE),
      y: clampTo(y, EDGE, window.innerHeight - h - EDGE),
    });

    // Diagnostics beacon: proves whether this module loaded, whether the slot
    // registration ran, and whether the component actually mounted.
    const report = (event, detail) => {
      try {
        fetch('/api/lan-peers/client-log', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ event, detail: detail == null ? null : String(detail).slice(0, 400) }),
        }).catch(() => {});
      } catch {}
    };
    report('module-loaded');
    try {
      window.addEventListener('error', (e) => report('window-error', (e && (e.message || e.error)) || 'unknown'));
      window.addEventListener('unhandledrejection', (e) => report('unhandled-rejection', (e && e.reason) || 'unknown'));
    } catch {}

    // S3：管理接口要会话 token。它由 panel.js（本机回环 host 直出的脚本）在加载时
    // 设到 window.__lanPeersToken；这里只是读。取不到就**不发请求**——那一定是 401，
    // 而一条 "token-required" 对用户毫无意义（React 半只在独立面板没接管时才会走到）。
    const adminToken = () => (typeof window.__lanPeersToken === 'string' ? window.__lanPeersToken : '');
    const api = (path, init) => {
      const token = adminToken();
      if (token === '') {
        // 由调用方识别 code（首屏据此安排一次重试），message 不面向用户展示。
        const error = new Error('管理接口未就绪（拿不到本机 token）');
        error.code = 'no-admin-token';
        return Promise.reject(error);
      }
      const options = Object.assign({}, init);
      const headers = Object.assign({}, options.headers);
      headers['X-Lan-Peers-Token'] = token;
      const verb = String(options.method || 'GET').toUpperCase();
      // 写操作服务端只收 JSON（text/plain 这类简单请求一律 415）。
      if (verb !== 'GET' && verb !== 'HEAD' && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
      options.headers = headers;
      return fetch('/api/lan-peers/' + path, options).then(async (res) => {
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || 'HTTP ' + res.status);
        return body;
      });
    };

    const S = {
      btn: {
        position: 'fixed', left: 16, bottom: 16, zIndex: 2147483000,
        border: '1px solid #3f6ae0', background: '#1b2333', color: '#dfe7ff',
        borderRadius: 999, padding: '8px 14px', fontSize: 13, cursor: 'grab',
        boxShadow: '0 6px 20px rgba(0,0,0,.35)',
        // Draggable launcher: pointer events only (no native scroll / text select).
        touchAction: 'none', userSelect: 'none', whiteSpace: 'nowrap',
      },
      panel: {
        position: 'fixed', left: 16, bottom: 64, width: 320, zIndex: 2147483000,
        background: '#161b22', color: '#e6edf3', border: '1px solid #30363d',
        borderRadius: 12, padding: 14, fontSize: 13, lineHeight: 1.5,
        boxShadow: '0 12px 40px rgba(0,0,0,.5)',
        maxHeight: '70vh', overflowY: 'auto', boxSizing: 'border-box',
      },
      label: { display: 'block', margin: '8px 0 4px', color: '#8b949e', fontSize: 12 },
      input: {
        width: '100%', boxSizing: 'border-box', background: '#0d1117',
        border: '1px solid #30363d', color: '#e6edf3', borderRadius: 6,
        padding: '6px 8px', fontSize: 12,
      },
      ghost: {
        marginTop: 8, background: '#21262d', border: '1px solid #30363d',
        color: '#e6edf3', borderRadius: 6, padding: '6px 10px', fontSize: 12, cursor: 'pointer',
      },
      primary: {
        marginTop: 8, background: '#1f6feb', border: 0, color: '#fff',
        borderRadius: 6, padding: '6px 10px', fontSize: 12, cursor: 'pointer',
      },
      code: { fontSize: 20, letterSpacing: 2, color: '#7ee787', marginTop: 6, fontFamily: 'ui-monospace, monospace' },
      hint: { color: '#8b949e', fontSize: 11, marginTop: 4 },
      peer: { borderTop: '1px solid #21262d', padding: '6px 0', fontSize: 12, color: '#c9d1d9' },
      msg: { marginTop: 8, fontSize: 12, minHeight: 16, color: '#f0883e' },
    };

    function LanPeersPanel() {
      const [open, setOpen] = useState(false);
      const [state, setState] = useState({ name: '', peers: [], pairing: null });
      const [name, setName] = useState('');
      const [code, setCode] = useState(null);
      const [url, setUrl] = useState('');
      const [peerName, setPeerName] = useState('');
      const [pairCode, setPairCode] = useState('');
      const [msg, setMsg] = useState('');
      const [left, setLeft] = useState(0);
      const [jobs, setJobs] = useState([]);
      const [unpairing, setUnpairing] = useState('');
      const timer = useRef(null);
      // S3：panel.js 是 defer 注入的，首屏第一次 GET state 可能比它先到。token 缺失
      // 时只安排一次重试（不轮询），拿到 token 就正常加载首屏。
      const tokenRetryRef = useRef(null);
      // One UI only. The body-level panel (panel.js) is immune to the slot
      // subtree's clipping/stacking problems, so when it takes over this
      // component stands down completely instead of leaving a second button.
      const [standDown, setStandDown] = useState(false);
      useEffect(() => {
        report('component-mounted');
        if (window.__dshLanPeersPanel) setStandDown(true);
        const onStandDown = () => setStandDown(true);
        try { window.addEventListener('dsh-lan-peers:standdown', onStandDown); } catch {}
        return () => { try { window.removeEventListener('dsh-lan-peers:standdown', onStandDown); } catch {} };
      }, []);
      const btnRef = useRef(null);
      const dragRef = useRef(null);
      const skipClickRef = useRef(false);
      const [pos, setPos] = useState(null);

      const btnSize = () => {
        const el = btnRef.current;
        return { w: el ? el.offsetWidth : 96, h: el ? el.offsetHeight : 36 };
      };
      const defaultPos = () => {
        const { w, h } = btnSize();
        return fitPos(window.innerWidth - w - 16, window.innerHeight - h - 16, w, h);
      };

      // A saved position can be off-screen if the window got smaller since the
      // drag (or the drag ended near an edge) — clamp it on load, not only on
      // resize, otherwise the launcher is invisible and looks "missing".
      useEffect(() => {
        const { w, h } = btnSize();
        const saved = readPos();
        setPos(saved ? fitPos(saved.x, saved.y, w, h) : defaultPos());
      }, []);
      useEffect(() => {
        const onResize = () => setPos((current) => {
          const { w, h } = btnSize();
          const base = current || defaultPos();
          return fitPos(base.x, base.y, w, h);
        });
        window.addEventListener('resize', onResize);
        return () => window.removeEventListener('resize', onResize);
      }, []);

      const onPointerDown = (event) => {
        if (event.button !== 0) return;
        // A drag that ends off-button may never emit click; never leave the
        // swallow flag armed, or the next real click would be ignored.
        skipClickRef.current = false;
        const el = btnRef.current;
        if (!el) return;
        const rect = el.getBoundingClientRect();
        dragRef.current = {
          pointerId: event.pointerId,
          dx: event.clientX - rect.left, dy: event.clientY - rect.top,
          startX: event.clientX, startY: event.clientY,
          w: rect.width, h: rect.height, moved: false,
        };
        if (el.setPointerCapture) el.setPointerCapture(event.pointerId);
      };
      const onPointerMove = (event) => {
        const drag = dragRef.current;
        if (!drag || drag.pointerId !== event.pointerId) return;
        // 4px threshold: below it this is still a click/tap, not a drag.
        if (!drag.moved && Math.abs(event.clientX - drag.startX) + Math.abs(event.clientY - drag.startY) < 4) return;
        drag.moved = true;
        if (btnRef.current) btnRef.current.style.cursor = 'grabbing';
        setPos(fitPos(event.clientX - drag.dx, event.clientY - drag.dy, drag.w, drag.h));
      };
      const endDrag = (event) => {
        const drag = dragRef.current;
        if (!drag || drag.pointerId !== event.pointerId) return;
        dragRef.current = null;
        const el = btnRef.current;
        if (el) {
          el.style.cursor = 'grab';
          if (el.releasePointerCapture) el.releasePointerCapture(event.pointerId);
        }
        if (!drag.moved) return;               // plain click falls through to onClick
        skipClickRef.current = true;
        setPos((current) => { if (current) writePos(current); return current; });
      };
      const onKeyDown = (event) => {
        const step = event.shiftKey ? 24 : 8;
        const delta = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[event.key];
        if (!delta) return;
        event.preventDefault();
        const { w, h } = btnSize();
        setPos((current) => {
          const base = current || defaultPos();
          const next = fitPos(base.x + delta[0], base.y + delta[1], w, h);
          writePos(next);
          return next;
        });
      };
      const panelPlacement = () => {
        const { h } = btnSize();
        const base = pos || defaultPos();
        const width = Math.min(320, window.innerWidth - 2 * EDGE);
        const left = clampTo(base.x, EDGE, window.innerWidth - width - EDGE);
        return base.y + h / 2 > window.innerHeight / 2
          ? { ...S.panel, left, width, bottom: Math.max(EDGE, window.innerHeight - base.y + 8) }
          : { ...S.panel, left, width, top: base.y + h + 8, bottom: 'auto' };
      };

      const refresh = useCallback(async () => {
        try {
          const st = await api('state');
          setState(st);
          setName((current) => current || st.name);
          // M6：state 不再回显配对码，只给 active / expiresInSec。刷新后码拿不回来，
          // 只剩倒计时 —— 码本身只在「生成配对码」那一次的响应里出现过。
          if (st.pairing && st.pairing.active) {
            const secs = Number(st.pairing.expiresInSec);
            setCode((current) => (current && current.code && current.expiresAt > Date.now()
              ? current
              : { code: '', expiresAt: Date.now() + (Number.isFinite(secs) && secs > 0 ? secs * 1000 : 0) }));
          }
        } catch (error) {
          // token 还没到（panel.js 尚未注入）：只安排一次 800ms 重试 —— 打开面板时
          // panel.js 也已经 defer 起来了，一次足够；始终拿不到就静默保持，不报错刷屏。
          if (error && error.code === 'no-admin-token') {
            if (!tokenRetryRef.current) {
              tokenRetryRef.current = setTimeout(() => {
                tokenRetryRef.current = null;
                refresh();
              }, 800);
            }
            return;
          }
          setMsg(String(error.message || error));
        }
      }, []);

      const pollJobs = useCallback(async () => {
        try {
          const out = await api('dispatch');
          setJobs(out.dispatches || []);
        } catch {
          // A missing dispatch feed is not worth an error banner.
        }
      }, []);

      useEffect(() => {
        if (!open) return;
        refresh();
        pollJobs();
        const handle = setInterval(pollJobs, 1000);
        return () => {
          clearInterval(handle);
          // 收起面板就不要再补一次首屏请求（重试只有一次，未触发就作废）。
          if (tokenRetryRef.current) {
            clearTimeout(tokenRetryRef.current);
            tokenRetryRef.current = null;
          }
        };
      }, [open, refresh, pollJobs]);

      useEffect(() => {
        if (!code || !code.expiresAt) return;
        clearInterval(timer.current);
        const tick = () => setLeft(Math.max(0, Math.floor((code.expiresAt - Date.now()) / 1000)));
        tick();
        timer.current = setInterval(tick, 1000);
        return () => clearInterval(timer.current);
      }, [code]);

      const saveName = async () => {
        setMsg('');
        try {
          const out = await api('name', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name }),
          });
          setMsg('名称已保存：' + out.name);
          refresh();
        } catch (error) {
          setMsg(String(error.message || error));
        }
      };

      const makeCode = async () => {
        setMsg('');
        try {
          const out = await api('code', { method: 'POST' });
          setCode({ code: out.code, expiresAt: out.expiresAt });
        } catch (error) {
          setMsg(String(error.message || error));
        }
      };

      const pair = async () => {
        setMsg('配对中…');
        try {
          const out = await api('pair', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, peerName, code: pairCode }),
          });
          setMsg('已与 ' + out.peer.name + ' 建立伙伴关系');
          setUrl('');
          setPeerName('');
          setPairCode('');
          refresh();
        } catch (error) {
          setMsg(String(error.message || error));
        }
      };

      const unpair = async (peer) => {
        const label = peer.name || peer.peerId;
        if (!window.confirm('解除与 ' + label + ' 的配对？对端在线时会同步删除。')) return;
        setMsg('解除中…');
        setUnpairing(peer.peerId);
        try {
          const out = await api('unpair', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ peerId: peer.peerId }),
          });
          const synced = !!(out.remote && out.remote.notified);
          setMsg('已解除与 ' + ((out.peer && out.peer.name) || label) + ' 的配对'
            + (synced ? '（对端已同步删除）' : '（仅本地）'));
          await refresh();
        } catch (error) {
          setMsg(String(error.message || error));
        } finally {
          setUnpairing('');
        }
      };

      if (standDown) return null;

      const mm = String(Math.floor(left / 60)).padStart(2, '0');
      const ss = String(left % 60).padStart(2, '0');

      const panel = open
        ? h('div', { style: panelPlacement() },
            h('div', { style: { fontWeight: 600, color: '#9ecbff' } }, '局域网伙伴'),
            h('label', { style: S.label }, '设备名称'),
            h('input', { style: S.input, value: name, maxLength: 64, onChange: (e) => setName(e.target.value) }),
            h('button', { style: S.ghost, onClick: saveName }, '保存名称'),
            h('label', { style: S.label }, '临时配对码'),
            h('button', { style: S.ghost, onClick: makeCode }, '生成配对码'),
            h('div', { style: S.code }, code && code.code ? code.code : (code ? '已生成' : '------')),
            h('div', { style: S.hint }, code
              ? (left > 0
                ? '已生成，剩余 ' + left + ' 秒（' + mm + ':' + ss + '）· 码只显示这一次，请现在抄下'
                : '已过期，请重新生成')
              : '生成后只显示一次，请立刻抄下（10 分钟内有效）'),
            h('label', { style: S.label }, '添加伙伴（对方地址 + 配对码）'),
            h('input', { style: S.input, placeholder: '192.168.1.10:7788', value: url, onChange: (e) => setUrl(e.target.value) }),
            h('input', { style: { ...S.input, marginTop: 6 }, placeholder: '对方名称（可选）', value: peerName, onChange: (e) => setPeerName(e.target.value) }),
            h('input', { style: { ...S.input, marginTop: 6 }, placeholder: '六位配对码', value: pairCode, onChange: (e) => setPairCode(e.target.value) }),
            h('button', { style: S.primary, onClick: pair }, '建立伙伴关系'),
            h('div', { style: { marginTop: 8 } },
              (state.peers.length ? state.peers : [{ peerId: 'x', name: '还没有伙伴', baseUrl: '' }]).map((p) =>
                h('div', {
                  key: p.peerId,
                  style: { ...S.peer, display: 'flex', gap: 6, alignItems: 'center', justifyContent: 'space-between' },
                },
                h('span', { style: { minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, p.name + (p.baseUrl ? ' · ' + p.baseUrl : '')),
                // Unpair is offered only for real peers, never for the placeholder row.
                state.peers.length
                  ? h('button', {
                      style: {
                        ...S.ghost, marginTop: 0, padding: '2px 8px', fontSize: 11, whiteSpace: 'nowrap', flexShrink: 0,
                        opacity: unpairing === p.peerId ? 0.5 : 1,
                        cursor: unpairing === p.peerId ? 'default' : 'pointer',
                      },
                      disabled: unpairing === p.peerId,
                      onClick: () => unpair(p),
                    }, '解除')
                  : null))),
            h('label', { style: S.label }, '派单实时状态'),
            h('div', null,
              (jobs.length ? jobs : [{ id: 'x', peer: '暂无派单记录', status: '', elapsedMs: 0, transport: '' }]).map((job) =>
                h('div', { key: job.id, style: { ...S.peer, display: 'flex', gap: 6, justifyContent: 'space-between' } },
                  h('span', null, job.peer + (job.status
                    ? ' · ' + job.status + ' · ' + Math.round((job.elapsedMs || 0) / 1000) + 's'
                    : '')),
                  h('span', {
                    style: {
                      whiteSpace: 'nowrap',
                      color: job.status === 'done'
                        ? '#7ee787'
                        : (job.status === 'error' || job.status === 'timeout') ? '#f85149' : '#f0883e',
                    },
                  }, job.transport || '')))),
            h('div', { style: S.msg }, msg))
        : null;

      return h('div', null,
        h('button', {
          ref: btnRef,
          'data-lan-peers-launcher': '1',
          // left/top are authoritative once measured; bottom is neutralised so the
          // default rule cannot fight the drag position.
          style: pos ? { ...S.btn, left: pos.x, top: pos.y, bottom: 'auto' } : S.btn,
          title: '拖动可移动 · 方向键微调 · 点击打开',
          onPointerDown,
          onPointerMove,
          onPointerUp: endDrag,
          onPointerCancel: endDrag,
          onKeyDown,
          onClick: () => {
            if (skipClickRef.current) { skipClickRef.current = false; return; }
            setOpen((v) => !v);
          },
        }, '🔗 伙伴'),
        panel);
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        try {
          report('slots', 'inject=' + typeof ctx.slots?.inject + ' register=' + typeof ctx.slots?.register);
          ctx.slots.inject('conversation.composer.dock', () =>
            ctx.slots.register({ name: 'conversation.composer.dock', id: 'lan-peers-dock', order: 5 }, LanPeersPanel));
          report('slot-registered');
        } catch (error) {
          report('slot-registration-failed', error && (error.message || error));
          console.error('dsh-lan-peers: slot registration failed', error);
        }

        // Self-healing: the composer dock may not be mounted yet (or at all) in
        // a given window, and then the slot never renders and the launcher is
        // simply absent. Fall back to the standalone injected panel, which is
        // the same UI the web client uses and guards itself against double load.
        // The launcher can be *in the DOM and still invisible*: an ancestor with
        // transform/filter turns position:fixed into container-relative, and any
        // overflow:hidden above it then clips the button away. So the fallback
        // tests real visibility, not mere existence, and reports the rect.
        const launcherVisible = () => {
          const node = document.querySelector('[data-lan-peers-launcher]');
          if (!node) { report('launcher-missing'); return false; }
          let rect;
          try { rect = node.getBoundingClientRect(); } catch { rect = null; }
          if (!rect) { report('launcher-no-rect'); return false; }
          report('launcher-rect', JSON.stringify({
            x: Math.round(rect.left), y: Math.round(rect.top),
            w: Math.round(rect.width), h: Math.round(rect.height),
            vw: window.innerWidth, vh: window.innerHeight,
          }));
          if (!rect.width || !rect.height) return false;
          const inViewport = rect.bottom > 0 && rect.right > 0 && rect.top < window.innerHeight && rect.left < window.innerWidth;
          if (!inViewport) return false;
          // A big z-index only wins inside its own stacking context: when an
          // ancestor (transform/filter) sits below a sibling, the button is
          // painted underneath and is invisible even though the rect looks
          // perfect. Hit-test the centre pixel to find out.
          try {
            const cx = rect.left + rect.width / 2;
            const cy = rect.top + rect.height / 2;
            const top = document.elementFromPoint(cx, cy);
            const reachable = !!top && (top === node || (node.contains && node.contains(top)));
            if (!reachable) {
              report('launcher-covered', JSON.stringify({
                by: top ? (top.tagName || '') + (top.className ? '.' + String(top.className).slice(0, 60) : '') : 'nobody',
                x: Math.round(cx), y: Math.round(cy),
              }));
              return false;
            }
          } catch (error) {
            report('launcher-hit-test-failed', error && (error.message || error));
          }
          return true;
        };
        let fallbackMounted = false;
        const describeAncestors = (node) => {
          const out = [];
          let current = node;
          for (let depth = 0; current && current !== document.body && depth < 10; depth++) {
            let style = {};
            try { style = window.getComputedStyle(current) || {}; } catch {}
            out.push([
              current.tagName || '?',
              String(current.className || '').slice(0, 40),
              'pos=' + (style.position || '-'),
              'ov=' + (style.overflow || '-'),
              'tr=' + (style.transform && style.transform !== 'none' ? 'yes' : 'no'),
              'op=' + (style.opacity || '-'),
              'vis=' + (style.visibility || '-'),
              'z=' + (style.zIndex || '-'),
            ].join(' '));
            current = current.parentElement;
          }
          return out.join(' <- ');
        };
        const mountFallback = (why) => {
          try {
            if (fallbackMounted || window.__dshLanPeersPanel) return;
            // The slot-rendered launcher lives inside the app's own subtree, so an
            // ancestor's transform/stacking context can clip or bury it — the rect
            // can even look perfect while nothing is painted. The standalone panel
            // is body-level and immune to that, so it is the primary UI here; the
            // React launcher stays as the fallback for when this fetch fails.
            launcherVisible();
            try {
              const probe = document.querySelector('[data-lan-peers-launcher]');
              if (probe) report('launcher-ancestors', describeAncestors(probe));
            } catch {}
            report('fallback-panel-inject', why);
            fallbackMounted = true;
            // Fetch the standalone panel and inline it: a relative /api fetch is
            // bridged through the app's IPC, while a <script src> under the
            // dsh-app:// scheme is not guaranteed to be served at all.
            fetch('/api/lan-peers/panel.js')
              .then((res) => {
                if (!res.ok) throw new Error('HTTP ' + res.status);
                return res.text();
              })
              .then((code) => {
                const inline = document.createElement('script');
                inline.textContent = code;
                document.body.appendChild(inline);
                // Only now drop the slot-rendered launcher: there must be exactly
                // one button, and if the fetch above had failed we keep the React
                // one visible.
                try {
                  for (const node of document.querySelectorAll('[data-lan-peers-launcher]')) node.style.display = 'none';
                  window.dispatchEvent(new Event('dsh-lan-peers:standdown'));
                } catch {}
                report('fallback-panel-injected', 'inline ' + code.length + 'B');
              })
              .catch((error) => {
                fallbackMounted = false;
                report('fallback-panel-inject-failed', error && (error.message || error));
              });
          } catch (error) {
            report('fallback-panel-failed', error && (error.message || error));
          }
        };
        try {
          setTimeout(() => mountFallback('after-1500ms'), 1500);
          setTimeout(() => mountFallback('after-4000ms'), 4000);
        } catch {}
      },
    };
  },
});
