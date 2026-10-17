import aesjs from "npm:aes-js@3.1.2";
import md5 from "npm:js-md5@0.8.3";

const STATIC_KEY_PART = "s0Rzj5P2";

const RESPONSE_UPDATE = "s;15806e558d99ab43afd65db8637a16528aaba8e3a766f1a006fbc0451b06a9c9";
const RESPONSE_LOAD = "s;15806e558d99ab43afd65db8637a1652fd4c2e3b3a5641e871509a61846da4f3b20d5b2c0a90a7c20f2f988f0c48aaf6";
const SUBSCRIPTION_DATA = "n;1;FollowBot;1;Undetected;1;2023-04-02 22:29:32;0;3;1;n;2;External Overlay;1;Undetected;1;2024-02-13 05:18:11;0;3;1;n;3;AutoBot";

const DEFAULT_HASH = "15839555f7729ab888e635fc14182de5";
const DEFAULT_HW = "8a07280d001E39491DD9";
const DEFAULT_CT = "87124431";

const PAYLOAD_URL = Deno.env.get("PAYLOAD_URL") ??
  "https://cdn.jsdelivr.net/gh/isakame/dlsjsa24112A_@main/payload.bin";

let encryptedCache = null;
let encryptedUptimeCache = null;

const te = new TextEncoder();
const td = new TextDecoder();

function normKey(key) {
  const raw = te.encode(key).slice(0, 16);
  const out = new Uint8Array(16);
  out.set(raw);
  return out;
}

function bytesToHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function pkcs7Pad(bytes) {
  const padLen = 16 - (bytes.length % 16);
  const out = new Uint8Array(bytes.length + padLen);
  out.set(bytes);
  out.fill(padLen, bytes.length);
  return out;
}

function pkcs7Unpad(bytes) {
  const padLen = bytes[bytes.length - 1];
  return bytes.slice(0, bytes.length - padLen);
}

function aes128EcbEncrypt(plaintext, key) {
  const ecb = new aesjs.ModeOfOperation.ecb(normKey(key));
  return ecb.encrypt(pkcs7Pad(te.encode(plaintext)));
}

function aes128EcbDecrypt(ciphertextHex, key) {
  const ecb = new aesjs.ModeOfOperation.ecb(normKey(key));
  return td.decode(pkcs7Unpad(ecb.decrypt(hexToBytes(ciphertextHex))));
}

function decryptDParam(encryptedD, eParam) {
  try {
    return aes128EcbDecrypt(encryptedD, eParam + STATIC_KEY_PART);
  } catch (_e) {
    return "";
  }
}

function extractParams(decryptedText) {
  const params = { ct: "", hw: DEFAULT_HW, hash: DEFAULT_HASH };
  const ct = decryptedText.match(/;&ct=(\d+);/);
  if (ct) params.ct = ct[1];
  const hw = decryptedText.match(/[;&]hw=([^;]+)/);
  if (hw) params.hw = hw[1];
  const hash = decryptedText.match(/[;&]hash=([^;]+)/);
  if (hash) params.hash = hash[1];
  return params;
}

function buildDynamicKey(hashValue) {
  return `8327447261105462922${hashValue}3w09jg405sdrign`;
}

function computeMd5(eParam, dynamicKey) {
  return md5(`${eParam}-${dynamicKey}`);
}

function rand6() {
  return Math.floor(Math.random() * 900000) + 100000;
}

function buildUptimePlaintext(params, eParam, dynamicKey) {
  const md5Hash = computeMd5(eParam, dynamicKey);
  let ctValue = DEFAULT_CT;
  if (params.ct) {
    const n = parseInt(params.ct, 10);
    if (!Number.isNaN(n)) ctValue = String(n + 586);
  }
  return `s;-8327447261105462922;${params.hash};${params.hw};0;${md5Hash};${ctValue};${rand6()};0982340980546234`;
}

function defaultUptimePlaintext(eParam) {
  const dynamicKey = buildDynamicKey(DEFAULT_HASH);
  const md5Hash = computeMd5(eParam, dynamicKey);
  return `s;-8327447261105462922;${DEFAULT_HASH};${DEFAULT_HW};0;${md5Hash};${DEFAULT_CT};${rand6()};0982340980546234`;
}

function text(body) {
  return new Response(body, { headers: { "Content-Type": "text/plain" } });
}

async function servePayload() {
  console.log(`[payload] proxy -> ${PAYLOAD_URL}`);
  const upstream = await fetch(PAYLOAD_URL);
  if (!upstream.ok || !upstream.body) return new Response("File not found", { status: 404 });
  const headers = new Headers();
  headers.set("Content-Type", "application/zip");
  headers.set("Content-Disposition", 'attachment; filename="poefollowbot.zip"');
  return new Response(upstream.body, { headers });
}

Deno.serve((request) => {
  const url = new URL(request.url);
  const path = url.pathname;
  const key = url.searchParams.get("key");
  const dParam = url.searchParams.get("d");

  console.log(`[req] ${request.method} ${path}${url.search || ""} | key=${key ? "yes" : "no"} d=${dParam ? "yes" : "no"}`);

  if (path === "/subscription") {
    if (key) {
      console.log(`[subscription] encrypting with key "${key}"`);
      encryptedCache = bytesToHex(aes128EcbEncrypt(SUBSCRIPTION_DATA, key + STATIC_KEY_PART));
      console.log("[subscription] encrypted");
    }
    if (encryptedCache === null) {
      console.log("[subscription] no key & no cache -> 503");
      return new Response("Service Unavailable", { status: 503 });
    }
    return text(`s;6;${encryptedCache}`);
  }

  if (path === "/update") return text(RESPONSE_UPDATE);
  if (path === "/load") return text(RESPONSE_LOAD);

  if (path === "/uptime") {
    if (key) {
      console.log(`[uptime] key "${key}", d=${dParam ? "yes" : "no"}`);
      let plaintext = defaultUptimePlaintext(key);
      if (dParam) {
        const decrypted = decryptDParam(dParam, key);
        if (decrypted) {
          console.log(`[uptime] decrypted d -> ${decrypted.slice(0, 100)}`);
          const params = extractParams(decrypted);
          console.log(`[uptime] ct=${params.ct || "(default)"} hw=${params.hw} hash=${params.hash}`);
          plaintext = buildUptimePlaintext(params, key, buildDynamicKey(params.hash));
        } else {
          console.log("[uptime] d decrypt failed, using default plaintext");
        }
      } else {
        console.log("[uptime] no d, using default plaintext");
      }
      encryptedUptimeCache = bytesToHex(aes128EcbEncrypt(plaintext, key + STATIC_KEY_PART));
      console.log("[uptime] encrypted");
    }
    if (encryptedUptimeCache === null) {
      console.log("[uptime] no key & no cache -> 503");
      return new Response("Service Unavailable", { status: 503 });
    }
    return text(`s;${encryptedUptimeCache}`);
  }

  return servePayload();
});
