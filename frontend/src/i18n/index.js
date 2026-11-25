import { startTranslating } from "./dom.js";
import { PATTERNS, PHRASES } from "./pt.js";
import { createTranslator } from "./translate.js";

const KEY = "horizon-language";
export const LANGUAGES = [["auto", "Automatic (follow Windows)"], ["en", "English"], ["pt", "Português"]];

const read = () => {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
};

/** The saved choice: "auto", "en" or "pt". */
export function getChoice() {
  const value = read();
  return LANGUAGES.some(([code]) => code === value) ? value : "auto";
}

/** The language actually used: an explicit choice, or Portuguese when the system language is Portuguese. */
export function activeLanguage() {
  const choice = getChoice();
  if (choice !== "auto") return choice;
  return (typeof navigator !== "undefined" && navigator.language || "en").toLowerCase().startsWith("pt") ? "pt" : "en";
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

export const translatePt = createTranslator(PHRASES, PATTERNS);

/** Call once at start-up. English needs nothing; Portuguese translates the page and keeps it translated. */
export function initLanguage(doc = document) {
  const language = activeLanguage();
  doc.documentElement.lang = language === "pt" ? "pt-PT" : "en";
  return language === "pt" ? startTranslating(doc, translatePt) : () => {};
}
