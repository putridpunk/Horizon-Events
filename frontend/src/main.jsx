import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import { routerFuture } from "./routerFuture.js";
import { initLanguage } from "./i18n/index.js";
import { initTheme } from "./theme/theme.js";
import "./theme.css";

initTheme();
initLanguage();

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter future={routerFuture}>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
