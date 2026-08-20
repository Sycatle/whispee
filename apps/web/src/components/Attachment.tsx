"use client";

import { useState } from "react";
import type { AttachmentRef } from "@/lib/attachments";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(1)} Mo`;
}

/**
 * Pièce jointe reçue.
 *
 * Le fichier est **téléchargé, jamais rendu inline**. Le type MIME vient de l'expéditeur :
 * c'est une indication, pas une preuve. Afficher un fichier déclaré `image/png` qui se
 * révèle être un SVG ou un HTML exécuterait du script sur cette origine — c'est-à-dire à
 * portée des clés dans IndexedDB. Un correspondant hostile, ou un compte compromis, suffit.
 *
 * Le nom aussi vient de l'expéditeur. Il est affiché comme texte, jamais interprété comme
 * un chemin.
 */
export function Attachment({
  attachment,
  onOpen,
}: {
  attachment: AttachmentRef;
  onOpen: () => Promise<Blob>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const download = async () => {
    setBusy(true);
    setError(null);
    try {
      const blob = await onOpen();

      // Le déchiffrement a réussi, donc l'AEAD a validé l'intégrité : ces octets sont bien
      // ceux qu'un membre du groupe a chiffrés, et n'ont pas été altérés en transit.
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = attachment.name;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      // Un échec ici n'est pas anodin : l'AEAD refuse un blob substitué ou altéré.
      setError(
        e instanceof Error && e.name === "OperationError"
          ? "Fichier illisible : il a été modifié ou remplacé depuis son envoi."
          : "Téléchargement impossible.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-1">
      <button
        type="button"
        onClick={download}
        disabled={busy}
        className="flex items-center gap-2 text-left underline disabled:opacity-60"
      >
        <span aria-hidden>📎</span>
        <span className="break-all">{attachment.name}</span>
      </button>
      <p className="text-xs opacity-70">
        {formatSize(attachment.size)}
        {busy && " — déchiffrement…"}
      </p>
      {error && (
        <p role="alert" className="text-xs text-(--color-danger)">
          {error}
        </p>
      )}
    </div>
  );
}
