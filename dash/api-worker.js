// api.cfpool.131433.xyz
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

      // ========= 过滤：国家 -> data_center =========
      if (loc) {
        const codes = LOC_MAP[loc.toUpperCase()] || [];
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

/* 卡片 */
.box {
  background: rgba(30, 41, 59, 0.85);
  padding: 36px;
  border-radius: 16px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  width: 420px;
  backdrop-filter: blur(10px);
}

/* 标题 */
h2 {
  margin: 0 0 18px 0;
  font-size: 22px;
  letter-spacing: 0.5px;
}

/* 输入框 */
input {
  width: 100%;
  padding: 14px 16px;
  border-radius: 10px;
  border: 1px solid #334155;
  background: #0f172a;
  color: white;
  font-size: 15px;
  outline: none;
  transition: all 0.2s ease;
}

/* focus 发光 */
input:focus {
  border-color: #38bdf8;
  box-shadow: 0 0 0 3px rgba(56,189,248,0.25);
}

/* 按钮 */
button {
  width: 100%;
  margin-top: 16px;
  padding: 12px;
  border: none;
  border-radius: 10px;
  background: linear-gradient(90deg, #3b82f6, #06b6d4);
  color: white;
  font-size: 15px;
  cursor: pointer;
  transition: 0.2s;
}

button:hover {
  transform: translateY(-1px);
  opacity: 0.95;
}

/* 小字 */
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

    <div class="tip">
      Secure API Dashboard · Authorization Required
    </div>
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
<h3>🔑 Auth Header</h3>
<code>Authorization: eulerme</code>
</div>

<div class="card">
<h3>📡 Endpoint</h3>
<code>/api</code>
</div>

<div class="card">
<h3>参数</h3>
<ul>
<li>?loc=TW</li>
<li>?port=443</li>
<li>?asn=3462</li>
<li>?sort=speed</li>
</ul>
</div>

<div class="card">
<h3>示例</h3>
<code>/api?loc=TW&sort=speed</code>
</div>

<div class="card">
<h3>原始数据查看</h3>
<span style="color: #800040;"><a href="https://raw.githubusercontent.com/fireinrain/nice-to-see-you/master/result.json" target="_blank">下载api数据</a></span>
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