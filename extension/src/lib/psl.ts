import { PSL_TEXT } from "./psl_data";

const MINIMAL_PSL = `
com
net
org
edu
gov
biz
info
uk
co.uk
org.uk
me.uk
za
co.za
org.za
br
com.br
net.br
org.br
jp
ac.jp
*.kyoto.jp
!ide.kyoto.jp
*.kobe.jp
!city.kobe.jp
*.ck
!www.ck
us
ak.us
k12.ak.us
// BEGIN PRIVATE DOMAINS
blogspot.com
github.io
pages.dev
workers.dev
netlify.app
vercel.app
weebly.com
wixsite.com
herokuapp.com
firebaseapp.com
web.app
glitch.me
duckdns.org
ngrok.io
000webhostapp.com
`;

export class PublicSuffixList {
  private readonly rules = new Set<string>();
  private readonly wildcards = new Set<string>();
  private readonly exceptions = new Set<string>();

  constructor(text = PSL_TEXT || MINIMAL_PSL) {
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim().toLowerCase();
      if (!line || line.startsWith("//")) continue;
      if (line.startsWith("!")) this.exceptions.add(line.slice(1));
      else if (line.startsWith("*.")) this.wildcards.add(line.slice(2));
      else this.rules.add(line);
    }
  }

  publicSuffix(hostname: string): string | null {
    const labels = hostname.toLowerCase().replace(/\.+$/, "").split(".");
    if (!labels[0]) return null;
    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join(".");
      if (this.exceptions.has(candidate)) return labels.slice(i + 1).join(".");
    }
    let best: string[] | null = null;
    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join(".");
      if (this.rules.has(candidate) && (!best || labels.length - i > best.length)) {
        best = labels.slice(i);
      }
      if (i > 0 && this.wildcards.has(candidate)) {
        const wildcard = labels.slice(i - 1);
        if (!best || wildcard.length > best.length) best = wildcard;
      }
    }
    return (best ?? [labels[labels.length - 1]]).join(".");
  }

  public registrableDomain(hostname: string): string | null {
    const host = hostname.toLowerCase().replace(/\.+$/, "");
    const suffix = this.publicSuffix(host);
    if (!suffix) return null;
    const labels = host.split(".");
    const suffixLabels = suffix.split(".");
    if (labels.length <= suffixLabels.length) return null;
    return labels.slice(labels.length - suffixLabels.length - 1).join(".");
  }
}

export function parsePsl(text: string): PublicSuffixList {
  return new PublicSuffixList(text);
}
