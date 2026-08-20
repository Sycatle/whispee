/**
 * Session gateway : une connexion, toutes les conversations.
 *
 * # Ce que ce module n'est pas
 *
 * Il n'est **pas** une source de vérité. Une trame `envelope` se contente de dire « va voir » ;
 * c'est la relève normale qui lit, vérifie l'appartenance et fait avancer le curseur. Une
 * session qui ne s'ouvre jamais laisse l'application entièrement fonctionnelle, simplement moins
 * réactive.
 *
 * Cette propriété n'est pas un luxe : une connexion dont la panne perdrait des messages serait
 * une connexion qu'il faudrait rendre fiable, et on aurait réinventé le transport au-dessus du
 * transport. Elle explique aussi pourquoi les curseurs envoyés à l'ouverture ne sont qu'une
 * optimisation — les ignorer coûterait une relève, pas un message.
 *
 * # Ce qu'elle retire au serveur
 *
 * La relève à 1,5 seconde envoyait une requête signée par conversation et par tour : un journal
 * d'activité à la seconde près. Le rattrapage par curseurs supprime en plus la relève de
 * réveil — le serveur ne répond que s'il a quelque chose à dire.
 *
 * # Ce qu'elle lui donne
 *
 * Un battement régulier, donc la présence. C'est le même compromis que documentait déjà le flux
 * SSE, à ceci près qu'il est ici explicite : le battement est une trame, pas un effet de bord.
 *
 * # Portée dynamique
 *
 * Contrairement au flux SSE qu'elle remplace, la portée n'est plus figée à l'ouverture. Une
 * conversation découverte en cours de route s'ajoute par une trame `subscribe`, sans rouvrir
 * la connexion ni refaire signer un défi.
 */
import { BASE_URL, type Api, type GatewayChallenge } from "./api";
import { fromBase64, fromHex, toBase64, toHex } from "./keys";

export interface GatewayHandlers {
  onEnvelope(groupId: Uint8Array, seq: number): void;
  onSignal(groupId: Uint8Array, payload: Uint8Array): void;
}

/** Plafond du délai de reconnexion. Au-delà, on martèle un serveur déjà en difficulté. */
const MAX_BACKOFF_MS = 30_000;

/** Dernière séquence connue d'une conversation, telle qu'annoncée à l'ouverture. */
export interface Cursor {
  groupId: Uint8Array;
  seq: number;
}

export class Gateway {
  private socket?: WebSocket;
  private closed = false;
  private attempt = 0;
  private heartbeat?: ReturnType<typeof setInterval>;

  /** Rythme imposé par le serveur, écrasé par la valeur annoncée dans `hello`. */
  private heartbeatMs = 30_000;

  /**
   * Groupes que cette session doit couvrir.
   *
   * Tenu ici plutôt que déduit à chaque reconnexion : le serveur abonne d'office aux groupes
   * dont l'appareil est membre, mais l'ensemble local est ce qui permet de rejouer les
   * `subscribe` après une coupure sans attendre la relève suivante.
   */
  private readonly scope = new Set<string>();

  constructor(
    private readonly api: Api,
    private readonly handlers: GatewayHandlers,
    /**
     * Curseurs au moment de la (re)connexion.
     *
     * Une fonction, pas une valeur : entre deux tentatives, la relève a pu avancer, et envoyer
     * un curseur périmé ferait réannoncer des séquences déjà lues.
     */
    private readonly cursors: () => Cursor[],
    /**
     * Construction du message signé, fournie par le module WebAssembly.
     *
     * Injectée plutôt qu'importée, pour la même raison que dans `api.ts` : ce module ne doit
     * pas dépendre du chargement du WASM, qui est asynchrone et n'a pas lieu au même moment.
     */
    private readonly challengeFormat: GatewayChallenge,
  ) {}

  start(): void {
    this.closed = false;
    void this.loop();
  }

  close(): void {
    this.closed = true;
    this.stopHeartbeat();
    this.socket?.close();
    this.socket = undefined;
  }

  /**
   * Ajoute une conversation à la portée de la session.
   *
   * Idempotent, et sûr hors connexion : la portée est mémorisée et rejouée à la reconnexion
   * suivante. C'est ce qui remplace la réouverture complète qu'imposait le flux SSE.
   */
  subscribe(groupId: Uint8Array): void {
    const key = toHex(groupId);
    if (this.scope.has(key)) return;

    this.scope.add(key);
    this.send({ op: "subscribe", group_id: key });
  }

  unsubscribe(groupId: Uint8Array): void {
    const key = toHex(groupId);
    if (!this.scope.delete(key)) return;

    this.send({ op: "unsubscribe", group_id: key });
  }

  /**
   * Relaie un signal éphémère par la session plutôt que par une requête HTTP.
   *
   * Le MAC de groupe reste ce qui l'authentifie : la session connaît notre identité, mais s'en
   * servir ici défairait le sealed sender. Le serveur applique exactement la même vérification
   * que sur le chemin HTTP.
   *
   * Retourne `false` si la session est fermée, l'appelant retombant alors sur la route HTTP.
   * Celle-ci est **elle aussi anonyme** : le repli ne dégrade donc rien du modèle de menace, il
   * coûte seulement une requête là où une trame aurait suffi.
   */
  signal(groupId: Uint8Array, nonce: Uint8Array, mac: Uint8Array, payload: Uint8Array): boolean {
    return this.send({
      op: "signal",
      group_id: toHex(groupId),
      nonce: toBase64(nonce),
      mac: toBase64(mac),
      payload: toBase64(payload),
    });
  }

  /** Vrai quand la socket est ouverte — sert à décider si un signal peut partir. */
  get live(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  private send(frame: Record<string, unknown>): boolean {
    if (!this.live) return false;

    this.socket?.send(JSON.stringify(frame));
    return true;
  }

  private async loop(): Promise<void> {
    while (!this.closed) {
      try {
        await this.session();
        // Terminaison propre du côté serveur : on repart sans pénalité.
        this.attempt = 0;
      } catch {
        // Volontairement muet. Une session coupée est un événement ordinaire — bascule de
        // réseau, veille de l'appareil, redémarrage du serveur — et le signaler à
        // l'utilisateur suggérerait à tort que quelque chose est perdu.
      }

      if (this.closed) return;

      const delay = Math.min(MAX_BACKOFF_MS, 500 * 2 ** this.attempt);
      this.attempt += 1;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  /** Une session, de l'ouverture à la fermeture. Résout à la fermeture, rejette sur erreur. */
  private session(): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = `${BASE_URL.replace(/^http/, "ws")}/v1/gateway`;
      const socket = new WebSocket(url);
      socket.binaryType = "arraybuffer";
      this.socket = socket;

      socket.onerror = () => reject(new Error("session gateway refusée"));

      socket.onclose = () => {
        this.stopHeartbeat();
        if (this.socket === socket) this.socket = undefined;
        resolve();
      };

      socket.onmessage = (event) => {
        if (typeof event.data !== "string") return;

        let frame: Record<string, unknown>;
        try {
          frame = JSON.parse(event.data) as Record<string, unknown>;
        } catch {
          // Une trame illisible est ignorée. La session n'est qu'un raccourci : ce qu'elle
          // laisse tomber, la relève périodique le rattrape.
          return;
        }

        void this.dispatch(socket, frame);
      };
    });
  }

  private async dispatch(socket: WebSocket, frame: Record<string, unknown>): Promise<void> {
    switch (frame.op) {
      case "hello":
        await this.identify(socket, frame);
        return;

      case "ready": {
        // La connexion tient : les tentatives suivantes repartent d'un délai court.
        this.attempt = 0;

        // Le serveur a abonné aux groupes dont il nous sait membre. Ceux que nous connaissons
        // et qu'il a omis sont réclamés explicitement — sans quoi une conversation créée
        // pendant une coupure resterait muette jusqu'à la relève suivante.
        const servis = new Set((frame.groups as string[] | undefined) ?? []);
        for (const key of this.scope) {
          if (!servis.has(key)) this.send({ op: "subscribe", group_id: key });
        }
        for (const key of servis) this.scope.add(key);

        this.startHeartbeat();
        return;
      }

      case "envelope":
        this.handlers.onEnvelope(fromHex(frame.group_id as string), frame.seq as number);
        return;

      case "signal":
        this.handlers.onSignal(
          fromHex(frame.group_id as string),
          fromBase64(frame.payload as string),
        );
        return;

      // `heartbeat_ack` et `error` ne demandent rien : le serveur ferme la socket quand une
      // erreur est fatale, et la boucle de reconnexion s'en charge. Réagir à un motif
      // d'erreur reviendrait à traiter comme une panne ce qui est le fonctionnement normal.
      default:
    }
  }

  /**
   * Relève le défi émis par le serveur.
   *
   * Le nonce vient du serveur et n'est valable qu'une fois : contrairement à l'authentification
   * HTTP, il n'y a **aucune** fenêtre pendant laquelle une signature captée resterait
   * utilisable. C'est ce que gagne une session en échange du fait de s'authentifier une seule
   * fois pour toute sa durée.
   */
  private async identify(socket: WebSocket, hello: Record<string, unknown>): Promise<void> {
    const nonce = fromBase64(hello.nonce as string);

    // Le rythme est dicté par le serveur, pas choisi ici : c'est lui qui sait au bout de
    // combien de silence il ferme. Le coder en dur des deux côtés les ferait diverger à la
    // première fois où l'un des deux changerait.
    const annonce = hello.heartbeat_ms;
    if (typeof annonce === "number" && annonce > 0) this.heartbeatMs = annonce;

    socket.send(
      JSON.stringify({
        op: "identify",
        device_id: this.api.deviceId,
        nonce: hello.nonce,
        signature: await this.api.signGatewayChallenge(nonce, this.challengeFormat),
        cursors: this.cursors().map((cursor) => ({
          group_id: toHex(cursor.groupId),
          seq: cursor.seq,
        })),
      }),
    );
  }

  /**
   * Bat au rythme annoncé par le serveur, divisé par deux.
   *
   * Le battement n'est pas qu'un signe de vie : c'est lui qui déclenche côté serveur la
   * revérification de nos appartenances. Le sauter laisserait la session servir des groupes
   * dont nous venons d'être retirés.
   */
  private startHeartbeat(): void {
    this.stopHeartbeat();
    // Deux fois plus vite que le rythme annoncé : un battement perdu sur une bascule de réseau
    // ne doit pas coûter une reconnexion, avec son défi et son rattrapage.
    this.heartbeat = setInterval(() => this.send({ op: "heartbeat" }), this.heartbeatMs / 2);
  }

  private stopHeartbeat(): void {
    if (this.heartbeat === undefined) return;

    clearInterval(this.heartbeat);
    this.heartbeat = undefined;
  }
}
