import { startTranslating } from "./dom.js";
import { buildPatterns } from "./patterns.js";
import { createTranslator } from "./translate.js";

const KEY = "horizon-language";

// code, the language's own name, writing direction, and a loader (each language is its own small file, fetched
// only when it is chosen)
const LANGS = {
  pt: ["Português", "ltr", () => import("./langs/pt.js")],
  fr: ["Français", "ltr", () => import("./langs/fr.js")],
  es: ["Español", "ltr", () => import("./langs/es.js")],
  de: ["Deutsch", "ltr", () => import("./langs/de.js")],
  it: ["Italiano", "ltr", () => import("./langs/it.js")],
  pl: ["Polski", "ltr", () => import("./langs/pl.js")],
  ru: ["Русский", "ltr", () => import("./langs/ru.js")],
  el: ["Ελληνικά", "ltr", () => import("./langs/el.js")],
  zh: ["中文（简体）", "ltr", () => import("./langs/zh.js")],
  ja: ["日本語", "ltr", () => import("./langs/ja.js")],
  ko: ["한국어", "ltr", () => import("./langs/ko.js")],
  ar: ["العربية", "rtl", () => import("./langs/ar.js")],
};

export const LANGUAGE_CODES = ["en", ...Object.keys(LANGS)];
export const LANGUAGES = [["auto", "Automatic (follow Windows)"], ["en", "English"], ...Object.entries(LANGS).map(([code, [name]]) => [code, name])];

const read = () => {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
};

/** The saved choice: "auto", "en" or a language code. */
export function getChoice() {
  const value = read();
  return LANGUAGES.some(([code]) => code === value) ? value : "auto";
}

/** The language actually used: an explicit choice, or the system language when it is one we have (else English). */
export function activeLanguage() {
  const choice = getChoice();
  if (choice !== "auto") return choice;
  const system = ((typeof navigator !== "undefined" && navigator.language) || "en").toLowerCase().split("-")[0];
  return system in LANGS ? system : "en";
}

/** Save the choice. The page is reloaded so every screen picks it up. */
export function setChoice(choice, reload = () => window.location.reload()) {
  try {
    localStorage.setItem(KEY, choice);
  } catch {
    /* the choice just will not be remembered */
  }
  reload();
}

/** The translate function for a language, or null for English (or a language that cannot be loaded). */
export async function loadTranslator(code) {
  if (!(code in LANGS)) return null;
  const { PHRASES, TEMPLATES } = await LANGS[code][2]();
  return createTranslator(PHRASES, buildPatterns(PHRASES, TEMPLATES));
}

/** Call once at start-up. English needs nothing; any other language translates the page and keeps it translated.
 *  Resolves to a function that stops translating. */
export async function initLanguage(doc = document) {
  const code = activeLanguage();
  const direction = code in LANGS ? LANGS[code][1] : "ltr";
  doc.documentElement.lang = code;
  doc.documentElement.dir = direction;
  let translate = null;
  try {
    translate = await loadTranslator(code);
  } catch {
    /* the language file could not be loaded: stay in English */
  }
  return translate ? startTranslating(doc, translate) : () => {};
}
