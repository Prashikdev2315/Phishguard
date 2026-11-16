import sensitive from "../../../lists/sensitive_words.json";
import action from "../../../lists/action_words.json";
import brands from "../../../lists/brands.json";
import shorteners from "../../../lists/shorteners.json";
import hosting from "../../../lists/hosting.json";
import { normalize } from "./normalize";

export const FEATURE_NAMES = [
  "url_length", "hostname_length", "path_length", "query_length", "fragment_length",
  "tld_length", "subdomain_count", "path_depth", "query_param_count", "dot_count",
  "hyphen_count", "underscore_count", "at_symbol_count", "double_slash_in_path",
  "non_default_port", "has_ip_host", "digit_count", "digit_ratio", "letter_ratio",
  "uppercase_ratio", "special_char_count", "special_char_ratio", "percent_encoded_count",
  "equals_count", "ampersand_count", "tilde_count", "sensitive_word_count",
  "action_word_count", "keyword_in_host", "keyword_in_path", "brand_in_subdomain_or_path",
  "is_url_shortener", "is_free_hosting", "registrable_domain_length", "domain_hyphen_count",
  "domain_digit_count", "is_punycode", "mixed_script_host", "suspicious_tld",
  "longest_subdomain_label", "embedded_url_in_path_or_query", "url_entropy", "host_entropy",
  "path_entropy", "query_entropy", "distinct_char_ratio", "max_digit_run",
  "max_consonant_run", "host_bigram_distinct_count", "host_trigram_distinct_count",
] as const;

export type FeatureName = typeof FEATURE_NAMES[number];
export type FeatureMap = Record<FeatureName, number>;
const words = (value: unknown, key: string): string[] =>
  Array.isArray(value) ? value.map(String).map((x) => x.toLowerCase()) :
  typeof value === "object" && value !== null && Array.isArray((value as Record<string, unknown>)[key])
    ? ((value as Record<string, unknown>)[key] as unknown[]).map(String).map((x) => x.toLowerCase()) : [];
const SENSITIVE = words(sensitive, "words");
const ACTION = words(action, "words");
const BRANDS = words(brands, "brands");
const SHORTENERS = words(shorteners, "shorteners");
const HOSTING = words(hosting, "platforms");

const entropy = (value: string): number => {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  return [...counts.values()].reduce((sum, count) => {
    const p = count / value.length;
    return sum - p * Math.log2(p);
  }, 0);
};
const countWords = (value: string, values: string[]): number =>
  values.reduce((count, word) => count + (word ? value.split(word).length - 1 : 0), 0);
const containsAny = (value: string, values: string[]): boolean => values.some((word) => word && value.includes(word));
const maxRun = (value: string, predicate: (char: string) => boolean): number => {
  let best = 0, current = 0;
  for (const char of value) {
    current = predicate(char) ? current + 1 : 0;
    best = Math.max(best, current);
  }
  return best;
};
const matchesDomain = (host: string, values: string[]): number =>
  Number(values.some((domain) => host === domain || host.endsWith(`.${domain}`)));
const mixedScript = (host: string): number => {
  const scripts = new Set<string>();
  for (const char of host) {
    if (!/\p{L}/u.test(char)) continue;
    if (/\p{Script=Latin}/u.test(char)) scripts.add("Latin");
    else if (/\p{Script=Cyrillic}/u.test(char)) scripts.add("Cyrillic");
    else if (/\p{Script=Greek}/u.test(char)) scripts.add("Greek");
    else scripts.add("Other");
  }
  return Number(scripts.size > 1);
};
const uniqueNgrams = (value: string, n: number): number => {
  const result = new Set<string>();
  for (let i = 0; i <= value.length - n; i++) result.add(value.slice(i, i + n));
  return result.size;
};

export function extractFeatures(url: string, suspiciousTlds: Record<string, boolean> = {}): FeatureMap {
  const result = normalize(url);
  if (result.error) throw new Error(`URL normalization failed: ${result.error}`);
  const host = result.puny_host.toLowerCase();
  const path = result.path;
  const query = result.query.startsWith("?") ? result.query.slice(1) : result.query;
  const fragment = result.fragment.startsWith("#") ? result.fragment.slice(1) : result.fragment;
  const lexical = result.normalized.replace(/^https?:\/\//i, "");
  const decodedLexical = result.decoded_url.replace(/^https?:\/\//i, "");
  const reg = result.registrable_domain ?? "";
  const labels = reg && !result.is_ip_host && host.endsWith(`.${reg}`)
    ? host.slice(0, -(reg.length + 1)).split(".").filter((label) => label && label !== "www") : [];
  const n = lexical.length;
  const tld = result.is_ip_host ? "" : (result.public_suffix ?? host.split(".").at(-1) ?? "");
  const value: Partial<FeatureMap> = {
    url_length: lexical.length, hostname_length: host.length, path_length: path.length,
    query_length: query.length, fragment_length: fragment.length,
    tld_length: result.is_ip_host ? 0 : tld.length, subdomain_count: result.is_ip_host ? 0 : labels.length,
    path_depth: path.split("/").filter(Boolean).length, query_param_count: query ? query.split("&").filter(Boolean).length : 0,
    dot_count: lexical.split(".").length - 1, hyphen_count: lexical.split("-").length - 1,
    underscore_count: lexical.split("_").length - 1, at_symbol_count: lexical.split("@").length - 1,
    double_slash_in_path: Number(path.includes("//")), non_default_port: Number(result.normalized.match(/:\d+(?:\/|$)/) !== null),
    has_ip_host: Number(result.is_ip_host), digit_count: [...lexical].filter((c) => /\d/u.test(c)).length,
    digit_ratio: n ? [...lexical].filter((c) => /\d/u.test(c)).length / n : 0,
    letter_ratio: n ? [...lexical].filter((c) => /\p{L}/u.test(c)).length / n : 0,
    uppercase_ratio: n ? [...lexical].filter((c) => /\p{Lu}/u.test(c)).length / n : 0,
    special_char_count: [...lexical].filter((c) => !/[\p{L}\p{N}]/u.test(c)).length,
    special_char_ratio: n ? [...lexical].filter((c) => !/[\p{L}\p{N}]/u.test(c)).length / n : 0,
    percent_encoded_count: (lexical.match(/%[0-9a-f]{2}/gi) ?? []).length,
    equals_count: (lexical.match(/=/g) ?? []).length, ampersand_count: (lexical.match(/&/g) ?? []).length,
    tilde_count: (lexical.match(/~/g) ?? []).length, sensitive_word_count: countWords(decodedLexical, SENSITIVE),
    action_word_count: countWords(decodedLexical, ACTION), keyword_in_host: Number(containsAny(host, [...SENSITIVE, ...ACTION])),
    keyword_in_path: Number(containsAny(path.toLowerCase(), [...SENSITIVE, ...ACTION])),
    brand_in_subdomain_or_path: Number(containsAny(`${labels.join(".")}/${path.toLowerCase()}`, BRANDS)),
    is_url_shortener: matchesDomain(host, SHORTENERS), is_free_hosting: matchesDomain(host, HOSTING),
    registrable_domain_length: result.is_ip_host ? 0 : reg.length,
    domain_hyphen_count: result.is_ip_host ? 0 : (reg.match(/-/g) ?? []).length,
    domain_digit_count: result.is_ip_host ? 0 : [...reg].filter((c) => /\d/u.test(c)).length,
    is_punycode: result.is_ip_host ? 0 : Number(result.is_punycode),
    mixed_script_host: result.is_ip_host ? 0 : mixedScript(result.display_host),
    suspicious_tld: Number(!result.is_ip_host && Boolean(suspiciousTlds[tld])),
    longest_subdomain_label: result.is_ip_host ? 0 : Math.max(0, ...labels.map((x) => x.length)),
    embedded_url_in_path_or_query: Number(/https?(?:%3a|:)(?:%2f|\/){2}/i.test(`${path}?${query}`)),
    url_entropy: entropy(lexical), host_entropy: entropy(host), path_entropy: entropy(path), query_entropy: entropy(query),
    distinct_char_ratio: n ? new Set(lexical).size / n : 0,
    max_digit_run: maxRun(lexical, (c) => /\d/u.test(c)),
    max_consonant_run: maxRun(lexical, (c) => /[bcdfghjklmnpqrstvwxyz]/i.test(c) && /\p{L}/u.test(c)),
    host_bigram_distinct_count: uniqueNgrams(host, 2), host_trigram_distinct_count: uniqueNgrams(host, 3),
  };
  return Object.fromEntries(FEATURE_NAMES.map((name) => [name, value[name] ?? 0])) as FeatureMap;
}

export function extractVector(url: string, suspiciousTlds?: Record<string, boolean>): Float32Array {
  const features = extractFeatures(url, suspiciousTlds);
  return new Float32Array(FEATURE_NAMES.map((name) => features[name]));
}
