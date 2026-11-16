export interface NormalizeResult {
  raw: string;
  error: string | null;
  normalized: string;
  cache_key: string;
  display_host: string;
  puny_host: string;
  registrable_domain: string | null;
  public_suffix: string | null;
  scheme: string;
  path: string;
  query: string;
  fragment: string;
  is_ip_host: boolean;
  is_punycode: boolean;
  decoded_url: string;
  raw_length: number;
}

export type ReasonCode =
  | "R-00" | "R-01" | "R-02" | "R-03" | "R-04" | "R-05"
  | "R-06" | "R-07" | "R-08" | "R-09" | "R-10" | "R-11";

export type RiskBand = "Safe" | "Suspicious" | "High-Risk";

export interface RiskVerdict {
  risk: number;
  probability: number;
  band: RiskBand;
  reasons: ReasonCode[];
}
