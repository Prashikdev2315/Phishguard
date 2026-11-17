import { FeatureMap } from "./features";
import { NormalizeResult, ReasonCode } from "./types";

export function reasonCodes(
  risk: number,
  features: FeatureMap,
  normalized: NormalizeResult,
  percentile = { url: 94, hostEntropy: 4.036006945330954 },
): ReasonCode[] {
  const reasons: ReasonCode[] = [];
  if (features.has_ip_host === 1) reasons.push("R-01");
  if (features.brand_in_subdomain_or_path === 1 && normalized.registrable_domain !== null) reasons.push("R-02");
  if (features.sensitive_word_count >= 2) reasons.push("R-03");
  if (features.url_length >= percentile.url) reasons.push("R-04");
  if (features.subdomain_count >= 4 || features.longest_subdomain_label >= 25) reasons.push("R-05");
  if (features.suspicious_tld === 1) reasons.push("R-06");
  if (features.is_punycode === 1 || features.mixed_script_host === 1) reasons.push("R-07");
  if (features.is_free_hosting === 1) reasons.push("R-08");
  if (features.at_symbol_count > 0 || features.embedded_url_in_path_or_query === 1) reasons.push("R-09");
  if (normalized.scheme === "http" && features.sensitive_word_count >= 1) reasons.push("R-10");
  if (features.host_entropy >= percentile.hostEntropy) reasons.push("R-11");
  if (risk >= 35 && reasons.length === 0) reasons.push("R-00");
  return reasons.slice(0, 3);
}
