import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import "./i18n";
import { registerServiceWorker } from "./lib/serviceWorker";

createRoot(document.getElementById("root")!).render(<App />);

registerServiceWorker();
