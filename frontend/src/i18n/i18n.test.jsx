import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import LanguageCard from "../components/settings/LanguageCard.jsx";
import { activeLanguage, getChoice, initLanguage, setChoice, translatePt } from "./index.js";
import { createTranslator } from "./translate.js";

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

describe("the Portuguese texts", () => {
  it("translate names inside patterns only when the name is known", () => {
    expect(translatePt("Repeated login failures from 192.168.1.15")).toBe("Falhas de início de sessão repetidas de 192.168.1.15");
    expect(translatePt("Account lockouts on account jsmith")).toBe("Bloqueios de conta na conta jsmith");
    // a log message that happens to end the same way is data, not interface text
    expect(translatePt("Accepted password for alice from 10.0.0.5")).toBe("Accepted password for alice from 10.0.0.5");
    expect(translatePt("HZ-001 · Repeated login failures")).toBe("HZ-001 · Falhas de início de sessão repetidas");
    expect(translatePt("5 minutes")).toBe("5 minutos");
    expect(translatePt("Created as OPEN")).toBe("Criado como ABERTO");
    expect(translatePt("OPEN → INVESTIGATING")).toBe("ABERTO → EM INVESTIGAÇÃO");
  });

  it("translate history lines that start with a bullet", () => {
    expect(translatePt("· Alert created by detection engine")).toBe("· Alerta criado pelo motor de deteção");
    expect(translatePt("· Opened automatically from ALT-000001")).toBe("· Aberto automaticamente a partir de ALT-000001");
    expect(translatePt("· a note the analyst typed")).toBe("· a note the analyst typed");
  });

  it("cover the navigation, severities and relative times", () => {
    expect(translatePt("Alerts")).toBe("Alertas");
    expect(translatePt("Critical")).toBe("Crítico");
    expect(translatePt("3 h ago")).toBe("há 3 h");
    expect(translatePt("just now")).toBe("agora mesmo");
    expect(translatePt("Scanning 2 of 5…")).toBe("A analisar 2 de 5…");
    expect(translatePt("1 threat found")).toBe("1 ameaça encontrada");
    expect(translatePt("Block 8.8.4.4 in Windows Firewall")).toBe("Bloquear 8.8.4.4 na Firewall do Windows");
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
    setChoice("pt", () => {});
    expect(activeLanguage()).toBe("pt");
  });

  it("ignores a stored value it does not know", () => {
    localStorage.setItem("horizon-language", "klingon");
    expect(getChoice()).toBe("auto");
  });

  it("saves the choice and reloads the page", async () => {
    const reload = vi.fn();
    setChoice("pt", reload);
    expect(localStorage.getItem("horizon-language")).toBe("pt");
    expect(reload).toHaveBeenCalled();
  });

  it("offers the three choices in the Settings card", async () => {
    render(<MemoryRouter><LanguageCard /></MemoryRouter>);
    const select = screen.getByLabelText("Language");
    expect([...select.options].map((o) => o.value)).toEqual(["auto", "en", "pt"]);
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

  it("translates what is on screen, what appears later and what changes", async () => {
    const stop = initLanguage(document);
    render(<Demo />, { container: document.body.appendChild(document.createElement("div")) });
    await waitFor(() => expect(screen.getByRole("heading")).toHaveTextContent("Alertas"));
    expect(document.documentElement.lang).toBe("pt-PT");
    expect(screen.getByText("há 1 min")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Pesquisar mensagem, utilizador, IP, anfitrião…")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Seguinte" }));
    await waitFor(() => expect(screen.getByText("há 2 min")).toBeInTheDocument());
    expect(screen.getByText("Crítico")).toBeInTheDocument();
    stop();
  });

  it("does not touch typed text, or elements marked translate=no", async () => {
    const stop = initLanguage(document);
    render(<Demo />, { container: document.body.appendChild(document.createElement("div")) });
    await waitFor(() => expect(screen.getByRole("heading")).toHaveTextContent("Alertas"));
    expect(document.querySelector("textarea")).toHaveValue("Alerts");
    expect(document.querySelector("[translate=no]")).toHaveTextContent("Alerts");
    stop();
  });

  it("does nothing in English", () => {
    localStorage.setItem("horizon-language", "en");
    const stop = initLanguage(document);
    render(<Demo />, { container: document.body.appendChild(document.createElement("div")) });
    expect(screen.getByRole("heading")).toHaveTextContent("Alerts");
    expect(document.documentElement.lang).toBe("en");
    stop();
  });
});
