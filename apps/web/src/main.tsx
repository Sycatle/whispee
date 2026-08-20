/**
 * Point d'entrée du client.
 *
 * Pas de `StrictMode`, et c'est délibéré : il monte puis démonte chaque effet une fois de plus
 * en développement. `Session` ouvre une socket et fait avancer un ratchet MLS dans ses effets —
 * les rejouer ferait consommer deux fois les mêmes clés de message, et MLS refuse la seconde
 * lecture. Le symptôme serait des messages perdus en développement seulement, ce qui est la
 * pire forme de divergence entre les deux environnements.
 */
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";

const racine = document.getElementById("root");
if (!racine) throw new Error("point de montage introuvable");

createRoot(racine).render(<App />);
