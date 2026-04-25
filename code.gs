/**
 * MasterHttpRelayVPN – Advanced Google Apps Script Relay
 * Features:
 * - Cache for GET requests (60s TTL)
 * - Gzip compression for responses >4KB
 * - Rate limiting (100 requests per minute per key)
 * - Automatic fallback if Cloudflare Worker fails
 * - Batch support with chunking (50 requests per chunk)
 */

const AUTH_KEY = "change_here";
const RATE_LIMIT = 100;        // requests per minute
const CACHE_TTL = 60;          // seconds
const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1,
  "proxy-authorization": 1, "priority": 1, te: 1,
};

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });

    // Ping test support
    if (req.u === "ping://test") return _json({ s: 200, h: {}, b: "" });

    // Rate limiting
    var cache = CacheService.getScriptCache();
    var rateKey = "rate_" + req.k;
    var count = cache.get(rateKey);
    if (count && parseInt(count) >= RATE_LIMIT) {
      return _json({ e: "rate_limit_exceeded" });
    }
    cache.put(rateKey, (parseInt(count)||0) + 1, 60);

    var workerUrl = req.w || null;
    if (Array.isArray(req.q)) return _doBatch(req.q, workerUrl);
    return _doSingle(req, workerUrl);
  } catch (err) {
    return _json({ e: String(err) });
  }
}

function _doSingle(req, workerUrl) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }

  var originalUrl = req.u;
  var useCache = (req.m === "GET" || !req.m) && !workerUrl;
  var cache = CacheService.getScriptCache();

  if (useCache) {
    var cached = cache.get(req.u);
    if (cached) return _json(JSON.parse(cached));
  }

  if (workerUrl) req.u = workerUrl + "?url=" + encodeURIComponent(req.u);

  var opts = _buildOpts(req);
  var resp;
  var fetchError = null;
  try {
    resp = UrlFetchApp.fetch(req.u, opts);
  } catch (err) {
    fetchError = err;
    if (workerUrl) {
      try {
        req.u = originalUrl;
        resp = UrlFetchApp.fetch(req.u, opts);
        fetchError = null;
      } catch (err2) {
        fetchError = err2;
      }
    }
  }

  if (fetchError) return _json({ e: "fetch_error: " + fetchError.toString() });

  var body = resp.getContent();
  var isLarge = body.length > 4096;
  var compression = (req.accept_encoding || "").includes("gzip") && isLarge;
  var response = { s: resp.getResponseCode(), h: _respHeaders(resp) };

  if (compression) {
    response.b = Utilities.base64Encode(Utilities.gzip(body));
    response.enc = "gzip";
  } else {
    response.b = Utilities.base64Encode(body);
  }

  if (useCache && resp.getResponseCode() === 200) {
    cache.put(originalUrl, JSON.stringify(response), CACHE_TTL);
  }
  return _json(response);
}

function _doBatch(items, workerUrl) {
  var requests = [];
  var errors = {};
  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    if (!item.u || !item.u.match(/^https?:\/\//i)) {
      errors[i] = "bad url";
      continue;
    }
    var originalUrl = item.u;
    if (workerUrl) item.u = workerUrl + "?url=" + encodeURIComponent(item.u);
    var opts = _buildOpts(item);
    requests.push(opts);
    if (workerUrl) opts._originalUrl = originalUrl;
  }

  // Chunk into 50 requests (safe limit for fetchAll)
  var chunkSize = 50;
  var allResponses = [];
  for (var j = 0; j < requests.length; j += chunkSize) {
    var chunk = requests.slice(j, j + chunkSize);
    var chunkResponses = UrlFetchApp.fetchAll(chunk);
    allResponses = allResponses.concat(chunkResponses);
  }

  var results = new Array(items.length);
  var rIdx = 0;
  for (var i = 0; i < items.length; i++) {
    if (errors[i]) {
      results[i] = { e: errors[i] };
      continue;
    }
    var resp = allResponses[rIdx++];
    if (!resp) {
      results[i] = { e: "no response" };
      continue;
    }
    var body = resp.getContent();
    var compression = (items[i].accept_encoding || "").includes("gzip") && body.length > 4096;
    var resultObj = { s: resp.getResponseCode(), h: _respHeaders(resp) };
    if (compression) {
      resultObj.b = Utilities.base64Encode(Utilities.gzip(body));
      resultObj.enc = "gzip";
    } else {
      resultObj.b = Utilities.base64Encode(body);
    }
    results[i] = resultObj;
  }
  return _json({ q: results });
}

function _buildOpts(req) {
  var method = (req.m || "GET").toUpperCase();
  var opts = {
    method: method,
    muteHttpExceptions: true,
    followRedirects: req.r !== false,
    validateHttpsCertificates: true,
    escaping: false
  };
  var hdrs = {};
  if (req.h) {
    for (var k in req.h) {
      if (!SKIP_HEADERS[k.toLowerCase()]) hdrs[k] = req.h[k];
    }
  }
  // Add natural browser headers if missing
  if (!hdrs["User-Agent"]) hdrs["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
  if (!hdrs["Accept"]) hdrs["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
  if (!hdrs["Accept-Language"]) hdrs["Accept-Language"] = "en-US,en;q=0.5";
  hdrs["sec-ch-ua"] = '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"';
  hdrs["sec-ch-ua-mobile"] = "?0";
  hdrs["sec-ch-ua-platform"] = '"macOS"';
  opts.headers = hdrs;

  if (req.b) {
    opts.payload = Utilities.base64Decode(req.b);
    if (req.ct) opts.contentType = req.ct;
  }
  return opts;
}

function _respHeaders(resp) {
  return resp.getAllHeaders ? resp.getAllHeaders() : resp.getHeaders();
}

function doGet(e) {
  return HtmlService.createHtmlOutput("<html><body><h1>MHRVPN Relay Active</h1></body></html>");
}

function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
