// The texts that carry numbers or names, and so are matched by a pattern instead of looked up whole. They are
// the same in every language; each language file supplies one template per pattern, in this order, using
// {1}, {2}, {3} for the captured parts and {T1}, {T2} for a captured part that is itself a translated phrase.
export const SOURCE_PATTERNS = [
  [/^just now$/, []],
  [/^(\d+) min ago$/, []],
  [/^(\d+) h ago$/, []],
  [/^(\d+) d ago$/, []],
  [/^Scanning (\d+) of (\d+)…$/, []],
  [/^1 threat found$/, []],
  [/^(\d+) threats found$/, []],
  [/^No threats found, 1 item could not be scanned$/, []],
  [/^No threats found, (\d+) items could not be scanned$/, []],
  [/^The scan stopped: (.*)$/, []],
  [/^Watching\. (\d+) scanned so far, (\d+) waiting\.$/, []],
  [/^Removed (\d+) old events\.$/, []],
  [/^Backup saved to (.*)\.$/, []],
  [/^Block (.*) in Windows Firewall$/, []],
  [/^Blocked until (.*)\.$/, []],
  [/^Remove suppression for (.*)$/, []],
  [/^rule (.*)$/, []],
  [/^address (.*)$/, []],
  [/^account (.*)$/, []],
  [/^rule (.*), address (.*)$/, []],
  [/^Created as (.+)$/, [1]],
  [/^(\w+) → (\w+)$/, [1, 2]],
  [/^Opened automatically from (.+)$/, []],
  [/^(.+) \(automatic\)$/, []],
  [/^(.+) \(manual\)$/, []],
  [/^(.+) removed by analyst$/, []],
  [/^(\d+) alert\(s\) merged in from (.+)$/, []],
  [/^Merged into (.+)$/, []],
  [/^(HZ-\d{3}) · (.+)$/, [2]],
  [/^(\d+) minutes$/, []],
  [/^(.+) on account (.+)$/, [1]],
  [/^(.+) from ([\d.:a-fA-F]+)$/, [1]],
  [/^for (.+)$/, []],
  [/^and account (.+)$/, []],
  [/^Event #(\d+)$/, []],
  [/^Listed on: (.+)$/, [1]],
  [/^Events are being collected \((.+)\)\.$/, []],
  [/^Trained (.+) on (\d+) per-IP hourly windows \((.+)\)\.\s*$/, []],
  [/^Service '(.+)' failed (\d+) times in (\d+) minutes\.$/, []],
  [/^A new (service|scheduled task) was created: (.*)\.$/, []],
  [/^Page (\d+) of (\d+)$/, []],
  [/^Waiting (.+); target for (.+) alerts is (.+)\.$/, [2]],
  [/^Alerts that would have been raised: (\d+)\. Events examined: (\d+), over the last (\d+) day\(s\)\.$/, []],
  [/^Of these, (\d+) already have an alert\.$/, []],
  [/^Showing the first (\d+)\.$/, []],
  [/^(\d+) (critical|high|medium|low)$/, [2]],
  [/^Most active: (.+)$/, []],
  [/^You have version (.+)\.$/, []],
  [/^Version (.+) is available\.$/, []],
  [/^Test message sent to (.+)\.$/, []],
  [/^Test to (.+) failed: (.+)$/, []],
  [/^List "(.+)" saved\. Addresses: (\d+)\. File hashes: (\d+)\. Domains: (\d+)\. Lines skipped: (\d+)\.$/, []],
  [/^Signed in as (.+) \((viewer|analyst|admin)\)\.$/, [2]],
  [/^Listening on (.+):(\d+) \(UDP and TCP\)\. Anything that can reach this port can add events, so only expose it to networks you trust\.$/, []],
  [/^New password for (.+) \(at least 12 characters\)$/, []],
  [/^New password for (.+)$/, []],
];

const fill = (template, groups, phrases) =>
  template.replace(/\{(T?)(\d)\}/g, (_, translated, n) => {
    const part = groups[Number(n) - 1];
    return translated ? phrases[part] ?? part : part;
  });

/** The pattern list for createTranslator, for one language's phrases and templates. */
export function buildPatterns(phrases, templates) {
  return SOURCE_PATTERNS.map(([pattern, known], i) => [
    pattern,
    (...groups) => {
      if (!templates[i] || known.some((n) => !Object.prototype.hasOwnProperty.call(phrases, groups[n - 1]))) return null;
      return fill(templates[i], groups, phrases);
    },
  ]);
}
