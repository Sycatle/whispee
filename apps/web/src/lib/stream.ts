/**
 * Flux temps réel : la latence, et rien d'autre.
 *
 * # Ce que ce module n'est pas
 *
 * Il n'est **pas** une source de vérité. Chaque événement se contente de dire « va voir » ;
 * c'est la relève normale qui lit, vérifie l'appartenance et fait avancer le curseur. Un flux
 * qui ne se connecte jamais laisse l'application entièrement fonctionnelle, simplement moins
 * réactive.
 *
 * Cette propriété n'est pas un luxe : un flux dont la panne perdrait des messages serait un
 * flux qu'il faudrait rendre fiable, et on aurait réinventé le transport au-dessus du
 * transport.
 *
 * # Ce qu'il retire au serveur
 *
 * Contre-intuitivement, de l'information. La relève à 1,5 seconde envoyait au serveur une
 * requête signée par conversation et par tour — un journal d'activité à la seconde près. Une
 * connexion longue le remplace par un seul point d'observation, à l'ouverture.
 *
 * # Portée figée
 *
 * Le serveur abonne aux groupes dont l'appareil est membre **au moment de l'ouverture**. Un
 * groupe rejoint ensuite n'est pas couvert : `Session` rouvre le flux quand elle en découvre
 * un, et la relève périodique sert de filet dans l'intervalle.
 */
import { BASE_URL, type Api } from "./api";
import { fromBase64, fromHex } from "./keys";

export interface StreamHandlers {
  onEnvelope(groupId: Uint8Array, seq: number): void;
  onSignal(groupId: Uint8Array, payload: Uint8Array): void;
}

/** Plafond du délai de reconnexion. Au-delà, on martèle un serveur déjà en difficulté. */
const MAX_BACKOFF_MS = 30_000;

export class Stream {
  private controller?: AbortController;
  private closed = false;
  private attempt = 0;

  constructor(
    private readonly api: Api,
    private readonly handlers: StreamHandlers,
  ) {}

  /**
   * Ouvre le flux et le maintient ouvert.
   *
   * Ne retourne pas de promesse à attendre : l'appelant continue son travail, et le flux vit
   * en arrière-plan jusqu'à `close()`. Une erreur n'est jamais propagée — elle déclenche une
   * reconnexion, parce qu'un flux interrompu n'est pas un échec de l'application.
   */
  start(): void {
    this.closed = false;
    void this.loop();
  }

  close(): void {
    this.closed = true;
    this.controller?.abort();
  }

  private async loop(): Promise<void> {
    while (!this.closed) {
      try {
        await this.session();
        // Terminaison propre du côté serveur : on repart sans pénalité.
        this.attempt = 0;
      } catch {
        // Volontairement muet. Un flux coupé est un événement ordinaire — bascule de réseau,
        // veille de l'appareil, redémarrage du serveur — et le signaler à l'utilisateur
        // suggérerait à tort que quelque chose est perdu.
      }

      if (this.closed) return;

      const delay = Math.min(MAX_BACKOFF_MS, 500 * 2 ** this.attempt);
      this.attempt += 1;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  private async session(): Promise<void> {
    this.controller = new AbortController();

    const response = await fetch(`${BASE_URL}/v1/stream`, {
      headers: await this.api.streamHeaders(),
      signal: this.controller.signal,
    });

    if (!response.ok || !response.body) throw new Error(`flux refusé : ${response.status}`);

    // La connexion tient : les tentatives suivantes repartent d'un délai court.
    this.attempt = 0;

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;

      buffer += decoder.decode(value, { stream: true });

      // Un événement SSE se termine par une ligne vide. Découper sur autre chose livrerait des
      // événements tronqués dès qu'un paquet TCP tombe au milieu d'un champ.
      let coupure = buffer.indexOf("\n\n");
      while (coupure !== -1) {
        this.dispatch(buffer.slice(0, coupure));
        buffer = buffer.slice(coupure + 2);
        coupure = buffer.indexOf("\n\n");
      }
    }
  }

  private dispatch(block: string): void {
    let event = "";
    let data = "";

    for (const line of block.split("\n")) {
      // Les lignes commençant par `:` sont des commentaires — c'est ainsi que le serveur
      // envoie ses keep-alive.
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) data += line.slice(5).trim();
    }

    if (!data) return;

    try {
      if (event === "envelope") {
        const payload = JSON.parse(data) as { groupId: string; seq: number };
        this.handlers.onEnvelope(fromHex(payload.groupId), payload.seq);
      } else if (event === "signal") {
        const payload = JSON.parse(data) as { groupId: string; payload: string };
        this.handlers.onSignal(fromHex(payload.groupId), fromBase64(payload.payload));
      }
    } catch {
      // Un événement illisible est ignoré. Le flux n'est qu'un raccourci : ce qu'il laisse
      // tomber, la relève périodique le rattrape.
    }
  }
}
