// Fuentes self-hosted estilo Illoca.com (Space Grotesk + Geist Mono + IBM Plex Mono)
import "@fontsource/space-grotesk/500.css";
import "@fontsource/space-grotesk/600.css";
import "@fontsource/space-grotesk/700.css";
import "@fontsource/geist-mono/400.css";
import "@fontsource/geist-mono/500.css";
import "@fontsource/geist-mono/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";

// Sistema de estilos: tokens → base → componentes → utilidades.
import "./styles/index.css";

import React from "react";
import ReactDOM from "react-dom/client";
import { TooltipProvider } from "./ui";
import App from "./App";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <TooltipProvider delayDuration={400} skipDelayDuration={300}>
      <App />
    </TooltipProvider>
  </React.StrictMode>,
);
