// Runtime translation of the interface. English is the source language: every screen is written in English, and
// when another language is chosen each piece of text is looked up here. Text with no translation stays English, so
// a missing entry is never a broken screen. `phrases` maps an exact English text to its translation; `patterns`
// handle text with numbers or names in it, e.g. "3 h ago".

const BULLET = "· ";
const SPACE = /^(\s*)([\s\S]*?)(\s*)$/;

/** @param {Record<string,string>} phrases  @param {Array<[RegExp, (...groups: string[]) => string]>} patterns */
export function createTranslator(phrases, patterns = []) {
  return function translate(text) {
    if (typeof text !== "string") return text;
    const [, lead, core, trail] = text.match(SPACE);
    if (!core) return text;
    if (Object.prototype.hasOwnProperty.call(phrases, core)) return lead + phrases[core] + trail;
    for (const [pattern, build] of patterns) {
      const m = core.match(pattern);
      const out = m && build(...m.slice(1));
      if (out != null) return lead + out + trail;  // a builder may decline (null) when a part is not a known phrase
    }
    if (core.startsWith(BULLET)) {  // "· note": history lines are prefixed with a bullet
      const rest = translate(core.slice(BULLET.length));
      if (rest !== core.slice(BULLET.length)) return lead + BULLET + rest + trail;
    }
    return text;
  };
}
