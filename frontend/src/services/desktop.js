// The desktop window offers the native Windows file and folder pickers as window.pywebview.api (see run_app.py).
// In a plain browser they do not exist.
const picker = () => (typeof window !== "undefined" ? window.pywebview?.api : undefined);

export const hasPicker = () => typeof picker()?.pick_files === "function";

/** Paths chosen in the native dialog; an empty list when the user cancels. */
export async function pickFiles() {
  return (await picker().pick_files()) ?? [];
}

export async function pickFolder() {
  return (await picker().pick_folder()) ?? [];
}

export const hasFileDialogs = () => typeof picker()?.pick_save_file === "function" && typeof picker()?.pick_file === "function";

/** Where to save a backup; an empty string when the user cancels. */
export async function pickSaveFile(suggestedName) {
  return (await picker().pick_save_file(suggestedName)) ?? "";
}

/** A single existing file; an empty string when the user cancels. */
export async function pickFile() {
  return (await picker().pick_file()) ?? "";
}
