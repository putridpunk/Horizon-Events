import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import LanguageCard from "../components/settings/LanguageCard.jsx";
import { LANGUAGE_CODES, LANGUAGES, activeLanguage, getChoice, initLanguage, loadTranslator, setChoice } from "./index.js";
import { SOURCE_PATTERNS } from "./patterns.js";
import { createTranslator } from "./translate.js";

const OTHER = LANGUAGE_CODES.filter((code) => code !== "en");
const placeholders = (text) => (text.match(/\{T?\d\}/g) ?? []).sort();

describe("createTranslator", () => {
  const tr = createTranslator({ Alerts: "Alertas", "Cancel": "Cancelar" }, [[/^(\d+) min ago$/, (n) => `há ${n} min`]]);

  it("translates exact texts and keeps the surrounding spaces", () => {
    expect(tr("Alerts")).toBe("Alertas");
    expect(tr("  Alerts\n")).toBe("  Alertas\n");
  });

  it("leaves texts with no translation exactly as they are", () => {
    for (const text of ["Something new", "alerts", "", "   ", "12"]) expect(tr(text)).toBe(text);
  });

  it("handles texts with numbers through patterns", () => {
    expect(tr("5 min ago")).toBe("há 5 min");
    expect(tr("5 mins ago")).toBe("5 mins ago");
  });

  it("is not fooled by names that are also object properties", () => {
    for (const text of ["constructor", "toString", "__proto__", "hasOwnProperty"]) expect(tr(text)).toBe(text);
  });

  it("passes non-strings through", () => {
    expect(tr(null)).toBeNull();
    expect(tr(undefined)).toBeUndefined();
  });
});

describe("every language", () => {
  it("offers 12 languages besides English, each with its own name", () => {
    expect(OTHER).toEqual(["pt", "fr", "es", "de", "it", "pl", "ru", "el", "zh", "ja", "ko", "ar"]);
    expect(LANGUAGES.map(([code]) => code)).toEqual(["auto", "en", ...OTHER]);
    expect(LANGUAGES.find(([code]) => code === "zh")[1]).toBe("中文（简体）");
  });

  it.each(OTHER)("%s: has a translation for every phrase and template, with the same placeholders as Portuguese", async (code) => {
    const reference = await import("./langs/pt.js");
    const lang = await import(`./langs/${code}.js`);
    expect(Object.keys(lang.PHRASES)).toEqual(Object.keys(reference.PHRASES));
    expect(lang.TEMPLATES).toHaveLength(SOURCE_PATTERNS.length);
    const empty = Object.entries(lang.PHRASES).filter(([, v]) => !v || !v.trim()).map(([k]) => k);
    expect(empty).toEqual([]);
    lang.TEMPLATES.forEach((template, i) => {
      expect(template, `template ${i}`).toBeTruthy();
      expect(placeholders(template), `template ${i}: ${template}`).toEqual(placeholders(reference.TEMPLATES[i]));
    });
  });

  it.each(OTHER)("%s: keeps language names and the product name as they are, and translates the rest", async (code) => {
    const { PHRASES } = await import(`./langs/${code}.js`);
    expect(PHRASES["English"]).toBe("English");
    expect(PHRASES["Português"]).toBe("Português");
    expect(PHRASES["Horizon Events"]).toBe("Horizon Events");
    expect(PHRASES["Alerts"]).not.toBe("Alerts");
    expect(PHRASES["Settings"]).not.toBe("Settings");
  });

  it.each(OTHER)("%s: translates relative times, counts and names inside patterns", async (code) => {
    const tr = await loadTranslator(code);
    expect(tr("3 h ago")).not.toBe("3 h ago");
    expect(tr("3 h ago")).toContain("3");
    expect(tr("Scanning 2 of 5…")).toMatch(/2.*5|5.*2/);
    expect(tr("Block 8.8.4.4 in Windows Firewall")).toContain("8.8.4.4");
    expect(tr("Repeated login failures from 192.168.1.15")).toContain("192.168.1.15");
    expect(tr("Repeated login failures from 192.168.1.15")).not.toMatch(/Repeated/);
  });

  it("translates names inside patterns only when the name is known", async () => {
    const tr = await loadTranslator("pt");
    expect(tr("Repeated login failures from 192.168.1.15")).toBe("Falhas de início de sessão repetidas de 192.168.1.15");
    expect(tr("Account lockouts on account jsmith")).toBe("Bloqueios de conta na conta jsmith");
    // a log message that happens to end the same way is data, not interface text
    expect(tr("Accepted password for alice from 10.0.0.5")).toBe("Accepted password for alice from 10.0.0.5");
    expect(tr("Created as OPEN")).toBe("Criado como ABERTO");
    expect(tr("OPEN → INVESTIGATING")).toBe("ABERTO → EM INVESTIGAÇÃO");
    expect(tr("HZ-001 · Repeated login failures")).toBe("HZ-001 · Falhas de início de sessão repetidas");
    expect(tr("A new service was created: EvilSvc.")).toBe("Foi criado(a) serviço: EvilSvc.");
  });

  it("translates history lines that start with a bullet, and leaves typed notes alone", async () => {
    const tr = await loadTranslator("pt");
    expect(tr("· Alert created by detection engine")).toBe("· Alerta criado pelo motor de deteção");
    expect(tr("· Opened automatically from ALT-000001")).toBe("· Aberto automaticamente a partir de ALT-000001");
    expect(tr("· a note the analyst typed")).toBe("· a note the analyst typed");
  });

  it("covers the navigation, severities and relative times in Portuguese", async () => {
    const tr = await loadTranslator("pt");
    expect(tr("Alerts")).toBe("Alertas");
    expect(tr("Critical")).toBe("Crítico");
    expect(tr("3 h ago")).toBe("há 3 h");
    expect(tr("just now")).toBe("agora mesmo");
    expect(tr("1 threat found")).toBe("1 ameaça encontrada");
  });

  it("returns nothing for English or an unknown language", async () => {
    expect(await loadTranslator("en")).toBeNull();
    expect(await loadTranslator("tlh")).toBeNull();
  });
});

describe("choosing a language", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  it("follows the system language by default, and an explicit choice wins", () => {
    vi.spyOn(navigator, "language", "get").mockReturnValue("pt-PT");
    expect(getChoice()).toBe("auto");
    expect(activeLanguage()).toBe("pt");
    setChoice("en", () => {});
    expect(activeLanguage()).toBe("en");
    vi.spyOn(navigator, "language", "get").mockReturnValue("en-US");
    expect(activeLanguage()).toBe("en");
    setChoice("de", () => {});
    expect(activeLanguage()).toBe("de");
  });

  it.each([["fr-FR", "fr"], ["es-MX", "es"], ["zh-CN", "zh"], ["zh-TW", "zh"], ["ru-RU", "ru"], ["pl", "pl"], ["de-AT", "de"],
    ["it-IT", "it"], ["el-GR", "el"], ["ja-JP", "ja"], ["ar-EG", "ar"], ["ko-KR", "ko"], ["sv-SE", "en"], ["en-GB", "en"]])(
    "Windows set to %s gives %s", (system, expected) => {
      vi.spyOn(navigator, "language", "get").mockReturnValue(system);
      expect(activeLanguage()).toBe(expected);
    });

  it("ignores a stored value it does not know", () => {
    localStorage.setItem("horizon-language", "klingon");
    expect(getChoice()).toBe("auto");
  });

  it("saves the choice and reloads the page", () => {
    const reload = vi.fn();
    setChoice("ja", reload);
    expect(localStorage.getItem("horizon-language")).toBe("ja");
    expect(reload).toHaveBeenCalled();
  });

  it("offers every language in the Settings card, each under its own name", () => {
    render(<MemoryRouter><LanguageCard /></MemoryRouter>);
    const select = screen.getByLabelText("Language");
    expect([...select.options].map((o) => o.value)).toEqual(["auto", "en", ...OTHER]);
    expect([...select.options].map((o) => o.textContent)).toContain("Русский");
    expect(select).toHaveValue("auto");
  });
});

describe("translating the page", () => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem("horizon-language", "pt");
    document.body.innerHTML = "";
  });
  afterEach(() => {
    localStorage.clear();
    document.documentElement.lang = "en";
    document.documentElement.dir = "ltr";
  });

  function Demo() {
    const [n, setN] = useState(1);
    return (
      <div>
        <h1>Alerts</h1>
        <p>{`${n} min ago`}</p>
        <input placeholder="Search message, user, IP, host…" aria-label="Alerts" />
        <textarea defaultValue="Alerts" />
        <button onClick={() => setN(n + 1)}>Next</button>
        {n > 1 && <span>Critical</span>}
        <span translate="no">Alerts</span>
      </div>
    );
  }

  const mount = () => render(<Demo />, { container: document.body.appendChild(document.createElement("div")) });

  it("translates what is on screen, what appears later and what changes", async () => {
    const stop = await initLanguage(document);
    mount();
    await waitFor(() => expect(screen.getByRole("heading")).toHaveTextContent("Alertas"));
    expect(document.documentElement.lang).toBe("pt");
    expect(document.documentElement.dir).toBe("ltr");
    expect(screen.getByText("há 1 min")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Pesquisar mensagem, utilizador, IP, anfitrião…")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Seguinte" }));
    await waitFor(() => expect(screen.getByText("há 2 min")).toBeInTheDocument());
    expect(screen.getByText("Crítico")).toBeInTheDocument();
    stop();
  });

  it("does not touch typed text, or elements marked translate=no", async () => {
    const stop = await initLanguage(document);
    mount();
    await waitFor(() => expect(screen.getByRole("heading")).toHaveTextContent("Alertas"));
    expect(document.querySelector("textarea")).toHaveValue("Alerts");
    expect(document.querySelector("[translate=no]")).toHaveTextContent("Alerts");
    stop();
  });

  it("switches the page to right-to-left for Arabic, and back for the others", async () => {
    localStorage.setItem("horizon-language", "ar");
    const stop = await initLanguage(document);
    mount();
    await waitFor(() => expect(screen.getByRole("heading")).toHaveTextContent("التنبيهات"));
    expect(document.documentElement.dir).toBe("rtl");
    expect(document.documentElement.lang).toBe("ar");
    stop();
    localStorage.setItem("horizon-language", "ja");
    document.body.innerHTML = "";
    const stopJa = await initLanguage(document);
    expect(document.documentElement.dir).toBe("ltr");
    mount();
    await waitFor(() => expect(screen.getByRole("heading")).toHaveTextContent("アラート"));
    stopJa();
  });

  it("does nothing in English", async () => {
    localStorage.setItem("horizon-language", "en");
    const stop = await initLanguage(document);
    mount();
    expect(screen.getByRole("heading")).toHaveTextContent("Alerts");
    expect(document.documentElement.lang).toBe("en");
    stop();
  });
});
