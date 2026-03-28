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
    // 🔐 /dash 口令验证
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
// 🚀 /api/one -> 单地区最快节点
// =====================
if (pathname === "/api/one") {
  const authHeader = request.headers.get("Authorization");

  if (authHeader !== AUTH_KEY) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "content-type": "application/json;charset=UTF-8" }
    });
  }

  // 👉 默认 JP
  let loc = url.searchParams.get("loc") || "JP";
  loc = loc.trim().toUpperCase();

  // 👉 只允许单个 loc（防止传 HK,JP）
  if (loc.includes(",")) {
    return new Response(JSON.stringify({ error: "Only single loc supported" }), {
      status: 400,
      headers: { "content-type": "application/json;charset=UTF-8" }
    });
  }

  // 👉 校验 loc 是否存在
  if (!LOC_MAP[loc]) {
    return new Response(JSON.stringify({ error: "Invalid loc" }), {
      status: 400,
      headers: { "content-type": "application/json;charset=UTF-8" }
    });
  }

  const codes = LOC_MAP[loc];

  const dataUrl =
    "https://raw.githubusercontent.com/fireinrain/nice-to-see-you/master/result.json";

  try {
    const resp = await fetch(dataUrl, {
      cf: { cacheTtl: 60 }
    });

    const raw = await resp.json();

    // 👉 过滤地区
    let filtered = raw.data.filter(item =>
      item.data_center && codes.includes(item.data_center)
    );

    if (!filtered.length) {
      return new Response(JSON.stringify({ error: "No data for loc" }), {
        status: 404,
        headers: { "content-type": "application/json;charset=UTF-8" }
      });
    }

    // 👉 排序（按 speed 最大）
    filtered.sort(
      (a, b) =>
        parseSpeed(b.download_speed) - parseSpeed(a.download_speed)
    );

    const best = filtered[0];

    return new Response(JSON.stringify({
      loc: loc,
      count: filtered.length,
      data: best
    }, null, 2), {
      headers: {
        "content-type": "application/json;charset=UTF-8",
        "access-control-allow-origin": "*",
        "cache-control": "public, max-age=60"
      }
    });

  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers: { "content-type": "application/json;charset=UTF-8" }
    });
  }
}

    // =====================
    // 🔐 /api 鉴权
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

    // 参数
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

      // ========= 过滤：支持多 loc =========
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

        // 去重
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

      // ========= 排序 =========
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

<p style="margin-top:10px;">用于获取指定地区中最优（速度最快）节点</p>

<h4>参数说明</h4>
<ul>
<li><code>?loc=JP</code> → 指定地区（默认 JP）</li>
</ul>

<div style="font-size:12px;color:#94a3b8;margin-top:6px;">
⚠ 仅支持单个 loc 参数（如 HK），不支持 HK,JP
</div>

<h4>示例</h4>
<ul>
<li><code>/api/one</code> → 默认 JP 最优节点</li>
<li><code>/api/one?loc=HK</code> → HK 最优节点</li>
<li><code>/api/one?loc=US</code> → US 最优节点</li>
</ul>

<h4>返回说明</h4>
<ul>
<li>返回单条最优节点数据</li>
<li>包含 loc / count / data 字段</li>
</ul>
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