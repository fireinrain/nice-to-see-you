// api.cfpool.131433.xyz

// api.cfpool.131433.xyz

// =====================
// 🌍 国家 -> data_center 映射
// =====================
const LOC_MAP = {
  SG: ["SIN"],
  HK: ["HKG"],
  TW: ["TPE", "KHH"],
  MO: ["MFM"],
  JP: ["FUK", "OKA", "KIX", "NRT"],
  KR: ["ICN"],
  US: ["LAX"]
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    const AUTH_KEY = "eulerme";

    // =====================
    // 🔐 /dash
    // =====================
    if (pathname === "/dash") {
      const auth = url.searchParams.get("auth");

      if (auth !== AUTH_KEY) {
        return new Response(getLoginHTML(), {
          headers: { "content-type": "text/html;charset=UTF-8" }
        });
      }

      return new Response(getDashboardHTML(), {
        headers: { "content-type": "text/html;charset=UTF-8" }
      });
    }

    // =====================
    // 🚀 /api/one
    // =====================
    if (pathname === "/api/one") {
  const authHeader = request.headers.get("Authorization");

  if (authHeader !== AUTH_KEY) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "content-type": "application/json;charset=UTF-8" }
    });
  }

  let loc = url.searchParams.get("loc") || "JP";
  loc = loc.trim().toUpperCase();

  if (loc.includes(",")) {
    return new Response(JSON.stringify({ error: "Only single loc supported" }), {
      status: 400,
      headers: { "content-type": "application/json;charset=UTF-8" }
    });
  }

  if (!LOC_MAP[loc]) {
    return new Response(JSON.stringify({ error: "Invalid loc" }), {
      status: 400,
      headers: { "content-type": "application/json;charset=UTF-8" }
    });
  }

  const codes = LOC_MAP[loc];

  const dataUrl =
    "https://raw.githubusercontent.com/fireinrain/nice-to-see-you/master/result.json";

  // =========================
  // 🧪 健康检测
  // =========================
  async function isAlive(node) {
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 1500);

        const resp = await fetch(`http://${node.ip}:${node.port}`, {
          method: "HEAD",
          signal: controller.signal
        });

        clearTimeout(timeout);

        return resp && resp.status < 500;
      } catch (e) {
        return false;
      }
  }

  try {
    const resp = await fetch(dataUrl, { cf: { cacheTtl: 60 } });
    const raw = await resp.json();

    let filtered = raw.data.filter(item =>
      item.data_center && codes.includes(item.data_center)
    );

    if (!filtered.length) {
      return new Response(JSON.stringify({ error: "No data for loc" }), {
        status: 404,
        headers: { "content-type": "application/json;charset=UTF-8" }
      });
    }

    const check = url.searchParams.get("check") === "1";
    const random = url.searchParams.get("random") === "1";

    let selected;

    // =====================================================
    // 🔥 模式1：random + check（只在 random 集合里循环）
    // =====================================================
    if (check && random) {
      let pool = [...filtered];

      while (pool.length > 0) {
        const idx = Math.floor(Math.random() * pool.length);
        const node = pool[idx];

        const ok = await isAlive(node);
        if (ok) {
          selected = node;
          break;
        }

        pool.splice(idx, 1);
      }

      if (!selected) {
        return new Response(JSON.stringify({ error: "No alive random node" }), {
          status: 503,
          headers: { "content-type": "application/json;charset=UTF-8" }
        });
      }

    // =====================================================
    // 🔥 模式2：speed + check（顺序检测，不随机）
    // =====================================================
    } else if (check) {
      filtered.sort(
        (a, b) =>
          parseSpeed(b.download_speed) - parseSpeed(a.download_speed)
      );

      for (const node of filtered) {
        const ok = await isAlive(node);
        if (ok) {
          selected = node;
          break;
        }
      }

      if (!selected) {
        return new Response(JSON.stringify({ error: "No alive speed node" }), {
          status: 503,
          headers: { "content-type": "application/json;charset=UTF-8" }
        });
      }

    // =====================================================
    // 🔥 模式3：无 check（原逻辑）
    // =====================================================
    } else {
      if (random) {
        const idx = Math.floor(Math.random() * filtered.length);
        selected = filtered[idx];
      } else {
        filtered.sort(
          (a, b) =>
            parseSpeed(b.download_speed) - parseSpeed(a.download_speed)
        );
        selected = filtered[0];
      }
    }

    return new Response(
      JSON.stringify(
        {
          loc,
          strategy:
            check && random
              ? "random-check"
              : check
              ? "speed-check"
              : random
              ? "random"
              : "speed",
          count: filtered.length,
          data: selected
        },
        null,
        2
      ),
      {
        headers: {
          "content-type": "application/json;charset=UTF-8",
          "access-control-allow-origin": "*",
          "cache-control": "public, max-age=30"
        }
      }
    );

  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers: { "content-type": "application/json;charset=UTF-8" }
    });
  }
}

    // =====================
    // 🔐 /api
    // =====================
    if (pathname.startsWith("/api")) {
      const authHeader = request.headers.get("Authorization");

      if (authHeader !== AUTH_KEY) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "content-type": "application/json;charset=UTF-8" }
        });
      }
    } else {
      return new Response("Not Found", { status: 404 });
    }

    // =====================
    // 📦 缓存
    // =====================
    const cache = caches.default;
    const cacheKey = new Request(url.toString(), request);

    let cached = await cache.match(cacheKey);
    if (cached) return cached;

    const loc = url.searchParams.get("loc");
    const port = url.searchParams.get("port");
    const asn = url.searchParams.get("asn");
    const sort = url.searchParams.get("sort");

    const dataUrl =
      "https://raw.githubusercontent.com/fireinrain/nice-to-see-you/master/result.json";

    try {
      const dataResp = await fetch(dataUrl, {
        cf: { cacheTtl: 60 }
      });

      const rawData = await dataResp.json();
      let resultData = rawData.data;

      if (loc) {
        const locList = loc
          .split(",")
          .map(v => v.trim().toUpperCase())
          .filter(Boolean);

        let codes = [];
        for (const l of locList) {
          if (LOC_MAP[l]) {
            codes.push(...LOC_MAP[l]);
          }
        }

        codes = [...new Set(codes)];

        resultData = resultData.filter(item =>
          item.data_center && codes.includes(item.data_center)
        );
      }

      if (port) {
        resultData = resultData.filter(
          item => String(item.port) === String(port)
        );
      }

      if (asn) {
        resultData = resultData.filter(
          item => String(item.asn) === String(asn)
        );
      }

      if (sort === "speed") {
        resultData.sort(
          (a, b) =>
            parseSpeed(b.download_speed) - parseSpeed(a.download_speed)
        );
      }

      if (sort === "latency") {
        resultData.sort(
          (a, b) =>
            parseLatency(a.network_latency) -
            parseLatency(b.network_latency)
        );
      }

      const result = {
        counts: resultData.length,
        last_check: rawData.last_check,
        data: resultData
      };

      const response = new Response(JSON.stringify(result, null, 2), {
        headers: {
          "content-type": "application/json;charset=UTF-8",
          "access-control-allow-origin": "*",
          "cache-control": "public, max-age=60"
        }
      });

      ctx.waitUntil(cache.put(cacheKey, response.clone()));
      return response;

    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500,
        headers: { "content-type": "application/json;charset=UTF-8" }
      });
    }
  }
};


// =====================
// 🔐 登录页面
// =====================
function getLoginHTML() {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>API Access</title>
<style>
body {
  margin: 0;
  font-family: ui-sans-serif, system-ui;
  background: radial-gradient(circle at top, #1e293b, #0f172a);
  color: white;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
}

.box {
  background: rgba(30, 41, 59, 0.85);
  padding: 36px;
  border-radius: 16px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  width: 420px;
  backdrop-filter: blur(10px);
}

h2 {
  margin: 0 0 18px 0;
  font-size: 22px;
}

input {
  width: 100%;
  padding: 14px 16px;
  border-radius: 10px;
  border: 1px solid #334155;
  background: #0f172a;
  color: white;
}

button {
  width: 100%;
  margin-top: 16px;
  padding: 12px;
  border: none;
  border-radius: 10px;
  background: linear-gradient(90deg, #3b82f6, #06b6d4);
  color: white;
  cursor: pointer;
}

.tip {
  font-size: 12px;
  color: #94a3b8;
  margin-top: 12px;
}
</style>
</head>

<body>
  <div class="box">
    <h2>🔐 API Access Gateway</h2>
    <form onsubmit="go(event)">
      <input id="key" placeholder="Enter access key..." />
      <button>Unlock Dashboard</button>
    </form>
    <div class="tip">Secure API Dashboard · Authorization Required</div>
  </div>

  <script>
    function go(e){
      e.preventDefault();
      const key = document.getElementById('key').value;
      location.href = "/dash?auth=" + encodeURIComponent(key);
    }
  </script>
</body>
</html>
  `;
}

// =====================
// 📄 Dashboard 页面
// =====================
function getDashboardHTML() {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>API Dashboard</title>
<style>
body { font-family: sans-serif; background:#0f172a; color:#e2e8f0; padding:40px;}
.card {background:#1e293b;padding:20px;border-radius:10px;margin-bottom:20px;}
code {background:#020617;padding:5px;border-radius:6px;color:#38bdf8;}
</style>
</head>
<body>

<h1>🚀 HTTP API Dashboard</h1>

<div class="card">
<h3>🔑 Authentication</h3>
<p>所有 API 请求必须携带 Header：</p>
<code>Authorization: eulerme</code>
</div>

<div class="card">
<h3>📡 通用查询接口</h3>
<code>/api</code>

<p style="margin-top:10px;">用于获取节点列表，支持多条件过滤与排序</p>

<h4>参数说明</h4>
<ul>
<li><code>?loc=TW</code> → 单地区过滤</li>
<li><code>?loc=TW,HK</code> → 多地区过滤（支持：SG, HK, MO, TW, JP, KR, US）</li>
<li><code>?port=443</code> → 端口过滤</li>
<li><code>?asn=3462</code> → ASN过滤</li>
<li><code>?sort=speed</code> → 按下载速度排序</li>
<li><code>?sort=latency</code> → 按延迟排序</li>
</ul>

<h4>示例</h4>
<code>/api?loc=TW,HK&sort=speed</code>

<h4>返回说明</h4>
<ul>
<li>返回符合条件的节点列表</li>
<li>包含 counts / last_check / data 字段</li>
</ul>
</div>

<div class="card">
<h3>⚡ 最优节点接口</h3>
<code>/api/one</code>

<p style="margin-top:10px;">
用于获取指定地区中最优节点（支持速度 / 随机 / 健康检测策略）
</p>

<h4>参数说明</h4>
<ul>
<li><code>?loc=JP</code> → 指定地区（默认 JP）</li>
<li><code>?random=1</code> → 随机返回节点</li>
<li><code>?check=1</code> → 启用健康检测（核心能力）</li>
</ul>

<div style="font-size:12px;color:#94a3b8;margin-top:6px;">
⚠ 仅支持单个 loc 参数（如 HK），不支持 HK,JP
</div>

---

<h4>🧠 执行策略说明（重要）</h4>

<div class="card">

<h4>1️⃣ speed 模式（默认）</h4>
<ul>
<li>不带 check 参数</li>
<li>按下载速度排序</li>
<li>直接返回最快节点</li>
</ul>

<code>/api/one?loc=JP</code>

---

<h4>2️⃣ random 模式（默认随机）</h4>
<ul>
<li>不带 check</li>
<li>随机返回一个节点</li>
</ul>

<code>/api/one?loc=JP&random=1</code>

---

<h4>3️⃣ speed + check（健康优先）</h4>
<ul>
<li>按速度排序</li>
<li>从最快开始逐个检测连通性</li>
<li>不可用 → 自动尝试下一个</li>
<li>不进行随机 fallback</li>
</ul>

<code>/api/one?loc=JP&check=1</code>

---

<h4>4️⃣ random + check（随机健康循环）🔥</h4>
<ul>
<li>从节点池中随机选择</li>
<li>对选中节点进行连通性检测</li>
<li>失败 → 重新 random 再试</li>
<li>成功 → 立即返回</li>
<li>不会回退 speed 顺序</li>
</ul>

<code>/api/one?loc=JP&check=1&random=1</code>

</div>

---

<h4>📦 返回说明</h4>

<ul>
<li>返回单条节点数据</li>
<li>包含 loc / strategy / count / data 字段</li>
</ul>

<pre><code>{
  "loc": "JP",
  "strategy": "speed | random | speed-check | random-check",
  "count": 12,
  "data": {
    "ip": "x.x.x.x",
    "port": 443,
    "download_speed": 1234,
    "data_center": "JP"
  }
}
</code></pre>

</div>
<div class="card" style="display: none">
<h3>原始数据查看</h3>
<span style="color: lawngreen;">
<a href="https://raw.githubusercontent.com/fireinrain/nice-to-see-you/master/result.json" target="_blank">
查看原始扫描结果
</a>
</span>
</div>

</body>
</html>
`;
}

// =====================
// 工具函数
// =====================
function parseSpeed(str) {
  return str ? parseFloat(str.replace(/[^\d.]/g, "")) : 0;
}

function parseLatency(str) {
  return str ? parseFloat(str.replace(/[^\d.]/g, "")) : 9999;
}