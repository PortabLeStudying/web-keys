"use strict";

const http = require("http");
const { URL } = require("url");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const MAX_BODY_BYTES = 10 * 1024 * 1024;

function send(res, statusCode, body, contentType = "text/plain; charset=utf-8") {
  const payload = Buffer.from(String(body));
  res.writeHead(statusCode, {
    "Content-Type": contentType,
    "Content-Length": payload.length
  });
  res.end(payload);
}

function parseBoundary(contentType) {
  const match = /(?:^|;\s*)boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || "");
  return match ? match[1] || match[2] : null;
}

function parseContentDisposition(value) {
  const result = {};
  for (const part of value.split(";")) {
    const [rawKey, ...rawValue] = part.trim().split("=");
    if (!rawKey || rawValue.length === 0) continue;
    const key = rawKey.toLowerCase();
    const joined = rawValue.join("=");
    result[key] = joined.replace(/^"|"$/g, "");
  }
  return result;
}

function parseMultipart(body, boundary) {
  const delimiter = Buffer.from(`--${boundary}`);
  const headerSeparator = Buffer.from("\r\n\r\n");
  const fields = new Map();
  let offset = body.indexOf(delimiter);

  while (offset !== -1) {
    offset += delimiter.length;

    if (body.slice(offset, offset + 2).toString() === "--") break;
    if (body.slice(offset, offset + 2).toString() === "\r\n") offset += 2;

    const next = body.indexOf(delimiter, offset);
    if (next === -1) break;

    let part = body.slice(offset, next);
    if (part.slice(-2).toString() === "\r\n") part = part.slice(0, -2);

    const headerEnd = part.indexOf(headerSeparator);
    if (headerEnd !== -1) {
      const rawHeaders = part.slice(0, headerEnd).toString("latin1");
      const content = part.slice(headerEnd + headerSeparator.length);
      const headers = new Map();

      for (const line of rawHeaders.split("\r\n")) {
        const colon = line.indexOf(":");
        if (colon === -1) continue;
        headers.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim());
      }

      const disposition = parseContentDisposition(headers.get("content-disposition") || "");
      if (disposition.name) {
        fields.set(disposition.name, {
          content,
          filename: disposition.filename || null,
          contentType: headers.get("content-type") || null
        });
      }
    }

    offset = next;
  }

  return fields;
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("Request body is too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function looksLikeBase64(value) {
  const compact = value.replace(/\s+/g, "");
  return compact.length > 0 && compact.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(compact);
}

function looksLikeBase64Url(value) {
  const compact = value.replace(/\s+/g, "");
  return compact.length > 0 && /^[A-Za-z0-9_-]+={0,2}$/.test(compact);
}

function looksLikeHex(value) {
  const compact = value.replace(/\s+/g, "");
  return compact.length > 0 && compact.length % 2 === 0 && /^[0-9a-f]+$/i.test(compact);
}

function addCandidate(candidates, seen, value) {
  if (!value || value.length === 0) return;
  const marker = value.toString("base64");
  if (seen.has(marker)) return;
  seen.add(marker);
  candidates.push(value);
}

function secretCandidates(secret) {
  const candidates = [];
  const seen = new Set();
  const text = secret.toString("utf8").trim();

  addCandidate(candidates, seen, secret);
  if (text !== secret.toString("utf8")) addCandidate(candidates, seen, Buffer.from(text, "utf8"));

  const dataUrl = /^data:[^,]+,(.+)$/i.exec(text);
  const encoded = dataUrl ? dataUrl[1] : text.replace(/^base64:/i, "");

  if (looksLikeBase64(encoded)) {
    addCandidate(candidates, seen, Buffer.from(encoded.replace(/\s+/g, ""), "base64"));
  }

  if (looksLikeBase64Url(encoded)) {
    let normalized = encoded.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4 !== 0) normalized += "=";
    addCandidate(candidates, seen, Buffer.from(normalized, "base64"));
  }

  if (looksLikeHex(text)) {
    addCandidate(candidates, seen, Buffer.from(text.replace(/\s+/g, ""), "hex"));
  }

  return candidates;
}

function decryptSecret(privateKey, secret) {
  const algorithms = [
    { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
    { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha512" },
    { padding: crypto.constants.RSA_PKCS1_PADDING }
  ];

  const errors = [];

  for (const input of secretCandidates(secret)) {
    for (const options of algorithms) {
      try {
        return crypto.privateDecrypt({ key: privateKey, ...options }, input).toString("utf8");
      } catch (error) {
        errors.push(error.message);
      }
    }
  }

  throw new Error(`Unable to decrypt secret: ${errors[0] || "unknown error"}`);
}

async function handleDecypher(req, res) {
  if (req.method !== "POST") {
    send(res, 405, "Method Not Allowed");
    return;
  }

  const boundary = parseBoundary(req.headers["content-type"]);
  if (!boundary) {
    send(res, 415, "Expected multipart/form-data");
    return;
  }

  let body;
  try {
    body = await readRequestBody(req);
  } catch (error) {
    send(res, 413, error.message);
    return;
  }

  const fields = parseMultipart(body, boundary);
  const key = fields.get("key");
  const secret = fields.get("secret");

  if (!key || !secret) {
    send(res, 400, "Fields key and secret are required");
    return;
  }

  try {
    const result = decryptSecret(key.content.toString("utf8").trim(), secret.content);
    send(res, 200, result);
  } catch (error) {
    send(res, 422, error.message);
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/login") {
    send(res, 200, "1154070");
    return;
  }

  if (url.pathname === "/decypher") {
    await handleDecypher(req, res);
    return;
  }

  if (url.pathname === "/") {
    send(res, 200, "web-keys");
    return;
  }

  send(res, 404, "Not Found");
});

server.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
