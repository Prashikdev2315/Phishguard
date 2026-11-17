import type { NormalizeResult } from "./types";
import { getUserAllowlist, setUserAllowlist } from "./storage";
const hostingDomains = new Set([
  "000webhostapp.com", "sites.google.com", "github.io", "pages.dev", "workers.dev",
  "netlify.app", "vercel.app", "blogspot.com", "weebly.com", "wixsite.com",
  "herokuapp.com", "firebaseapp.com", "web.app", "glitch.me", "duckdns.org", "ngrok.io",
]);
const defaults = new Set<string>();
const domainMatches = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);
export function isHostingDomain(domain: string | null): boolean {
  return !!domain && hostingDomains.has(domain);
}
export function canAllowlist(host: string, normalized: NormalizeResult): boolean {
  return !isHostingDomain(normalized.registrable_domain) || host !== normalized.registrable_domain;
}
export function isDefaultAllowed(normalized: NormalizeResult): boolean {
  return [...defaults].some(domain => domainMatches(normalized.puny_host, domain));
}
export async function isUserAllowed(normalized: NormalizeResult): Promise<boolean> {
  const list = await getUserAllowlist();
  return list.some(domain => domainMatches(normalized.puny_host, domain));
}
export async function addUserAllowed(host: string, normalized: NormalizeResult): Promise<boolean> {
  if (!canAllowlist(host, normalized)) return false;
  const list = await getUserAllowlist();
  if (!list.includes(host)) await setUserAllowlist([...list, host]);
  return true;
}
