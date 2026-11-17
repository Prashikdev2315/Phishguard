import punycode from "punycode";
import { NormalizeResult } from "./types";
import { PublicSuffixList } from "./psl";

export const MAX_URL_LENGTH = 2048;
const TRACKING = new Set(["fbclid", "gclid", "msclkid"]);
const BOM = new Set(["\ufeff", "\ufffe", "\u00a0"]);
const DEFAULT_PSL = new PublicSuffixList();

function trimOuter(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && (BOM.has(value[start]) || /\s/u.test(value[start]))) start++;
  while (end > start && (BOM.has(value[end - 1]) || /\s/u.test(value[end - 1]))) end--;
  return value.slice(start, end);
}

function isIpHost(host: string): boolean {
  const value = host.toLowerCase().replace(/\.$/, "");
  if (/^\[.*\]$/.test(value)) return true;
  if (/^0x[0-9a-f]{1,8}$/i.test(value)) return Number.parseInt(value, 16) <= 0xffffffff;
  if (/^\d+$/.test(value)) return Number(value) <= 0xffffffff;
  if (/^0[0-7]*\.0[0-7]*\.0[0-7]*\.0[0-7]*$/.test(value)) return true;
  const octets = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return octets !== null && octets.slice(1).every((part) => Number(part) <= 255);
}

function resolvePath(path: string): string {
  if (!path) return path;
  const output: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === ".") continue;
    if (segment === "..") {
      if (output.length && output[output.length - 1] !== "") output.pop();
    } else output.push(segment);
  }
  let result = output.join("/");
  if (path.startsWith("/") && !result.startsWith("/")) result = `/${result}`;
  return result;
}

function stripTracking(query: string): string {
  return query.split("&").filter((part) => {
    const name = part.split("=", 1)[0].toLowerCase();
    return !name.startsWith("utm_") && !TRACKING.has(name);
  }).join("&");
}

function emptyResult(raw: string, error: string): NormalizeResult {
  return {
    raw, error, normalized: "", cache_key: "", display_host: "", puny_host: "",
    registrable_domain: null, public_suffix: null, scheme: "", path: "", query: "",
    fragment: "", is_ip_host: false, is_punycode: false, decoded_url: "", raw_length: 0,
  };
}

function safeUnquote(url: string): string {
  return url.replace(/(%[0-9a-fA-F]{2})+/g, (match) => {
    try {
      return decodeURIComponent(match);
    } catch {
      const bytes: number[] = [];
      for (let i = 0; i < match.length; i += 3) {
        bytes.push(parseInt(match.slice(i + 1, i + 3), 16));
      }
      return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
    }
  });
}

export function normalize(raw: string, psl = DEFAULT_PSL): NormalizeResult {
  const cleaned = trimOuter(raw);
  if (cleaned.length > MAX_URL_LENGTH) return emptyResult(raw, "url_too_long");
  if (/\s/u.test(cleaned)) return emptyResult(raw, "whitespace_inside");
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(cleaned) ? cleaned : `http://${cleaned}`;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return emptyResult(raw, "invalid_url");
  }
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  if (scheme !== "http" && scheme !== "https" || !parsed.hostname) return emptyResult(raw, "invalid_url");
  const authorityText = withScheme.slice(withScheme.indexOf("://") + 3).split(/[/?#]/, 1)[0];
  const hostText = authorityText.includes("@") ? authorityText.split("@").at(-1)! : authorityText;
  const displayHost = (hostText.startsWith("[") ? hostText.slice(0, hostText.indexOf("]") + 1) : hostText.split(":")[0])
    .toLowerCase().replace(/\.$/, "");
  const labels = displayHost.split(".");
  const punyHost = labels.map((label) => {
    try { return punycode.toASCII(label); } catch { return label; }
  }).join(".");
  const ip = isIpHost(displayHost);
  const port = parsed.port && !((scheme === "http" && parsed.port === "80") || (scheme === "https" && parsed.port === "443"))
    ? `:${parsed.port}` : "";
  const authorityStart = withScheme.indexOf("://") + 3;
  const relative = withScheme.slice(authorityStart);
  const authorityEnd = relative.search(/[/?#]/);
  const remainder = authorityEnd < 0 ? "" : relative.slice(authorityEnd);
  const rawPath = remainder.split(/[?#]/, 1)[0];
  const pathWithoutParams = rawPath.replace(/;[^/]*$/, "");
  let path = resolvePath(pathWithoutParams);
  if (path === "/") path = "";
  const query = parsed.search;
  const fragment = parsed.hash;
  const authority = `${punyHost}${port}`;
  const featurePunyHost = punyHost.startsWith("www.") ? punyHost.slice(4) : punyHost;
  const featureAuthority = `${featurePunyHost}${port}`;
  const normalized = `${scheme}://${featureAuthority}${path}${query}${fragment}`;
  if (normalized.length > MAX_URL_LENGTH) return emptyResult(raw, "url_too_long");
  const cacheQuery = stripTracking(query.replace(/^\?+/, ""));
  const cacheKey = `${scheme}://${authority}${path}${cacheQuery ? `?${cacheQuery}` : ""}`;
  const suffix = ip ? null : psl.publicSuffix(punyHost);
  const registrable = ip ? null : psl.registrableDomain(punyHost);
  const decoded = safeUnquote(normalized);
  return {
    raw, error: null, normalized, cache_key: cacheKey, display_host: displayHost,
    puny_host: punyHost, registrable_domain: registrable, public_suffix: suffix,
    scheme, path, query, fragment, is_ip_host: ip, is_punycode: punyHost.includes("xn--"),
    decoded_url: decoded.toLowerCase(), raw_length: normalized.length,
  };
}
