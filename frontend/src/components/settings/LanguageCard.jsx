import { LANGUAGES, getChoice, setChoice } from "../../i18n/index.js";

/** The interface language. The page reloads so that every screen picks the new language up. */
export default function LanguageCard() {
  return (
    <section className="card">
      <h2>Language</h2>
      <div className="settings-form">
        <label>
          Language
          <select value={getChoice()} onChange={(e) => setChoice(e.target.value)}>
            {LANGUAGES.map(([code, label]) => <option key={code} value={code}>{label}</option>)}
          </select>
        </label>
      </div>
    </section>
  );
}
