import type { ReasonCode } from "./types";

export const REASON_TEXT: Record<ReasonCode, string> = {
  "R-00": "The address has a suspicious overall risk pattern.",
  "R-01": "The address uses an IP host.",
  "R-02": "A brand appears outside its expected domain.",
  "R-03": "Sensitive action words appear repeatedly.",
  "R-04": "The address is unusually long.",
  "R-05": "The host has unusually deep subdomains.",
  "R-06": "The top-level domain is associated with elevated risk.",
  "R-07": "The host may use look-alike characters.",
  "R-08": "The host uses free or shared hosting.",
  "R-09": "The address embeds another URL.",
  "R-10": "Sensitive terms are used without HTTPS.",
  "R-11": "The host has high randomness.",
};
export const formatHost = (displayHost: string, punyHost: string): string =>
  displayHost && punyHost && displayHost !== punyHost ? `${displayHost} (${punyHost})` : displayHost || punyHost;
