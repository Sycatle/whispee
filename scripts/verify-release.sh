#!/usr/bin/env bash
#
# Vérifie une publication de l'application de bureau.
#
# # À qui ce script est destiné
#
# À celui qui **reçoit** le binaire, pas à celui qui le produit. Il ne demande donc aucune clé
# privée et ne dépend que d'`openssl` : il doit pouvoir tourner sur une machine qui n'a rien de
# ce projet, à part la clé publique et les fichiers publiés.
#
# # Ce qu'il établit
#
# Que la publication a été signée par le détenteur de la clé privée correspondante, et que les
# fichiers n'ont pas changé depuis. Rien de plus.
#
# # Ce qu'il n'établit pas
#
# * **Que cette clé publique soit la bonne.** C'est du trust on first use, exactement comme
#   l'enregistrement d'un compte : rien ne prouve que la première clé rencontrée soit légitime.
#   La clé vit dans le dépôt, donc qui contrôle le dépôt peut la remplacer en même temps que le
#   binaire. La seule protection réelle est de comparer son empreinte hors bande — le même geste
#   que la vérification d'empreinte de compte que l'application demande déjà.
# * **Que le binaire corresponde au code.** Cela se constate en le reconstruisant depuis le
#   commit indiqué dans `BUILD-INFO`, avec les mêmes versions d'outillage, et en comparant les
#   empreintes. La signature authentifie l'éditeur ; seule la reconstruction authentifie le code.
#
# # Usage
#
#   scripts/verify-release.sh [repertoire] [cle-publique]
#
# Par défaut : `release/artefacts` et `release/whispee.pub`.
set -euo pipefail

artefacts="${1:-release/artefacts}"
publique="${2:-release/whispee.pub}"

for fichier in "$artefacts/SHA256SUMS" "$artefacts/SHA256SUMS.sig" "$publique"; do
    if [[ ! -r "$fichier" ]]; then
        echo "erreur : fichier manquant ou illisible : $fichier" >&2
        exit 1
    fi
done

# La signature d'abord, les empreintes ensuite. L'inverse validerait des empreintes que
# n'importe qui aurait pu réécrire en même temps que le binaire : le fichier d'empreintes ne
# vaut que par la signature qui le couvre.
if ! openssl pkeyutl -verify -rawin -pubin -inkey "$publique" \
    -in "$artefacts/SHA256SUMS" -sigfile "$artefacts/SHA256SUMS.sig" >/dev/null 2>&1; then
    echo "ÉCHEC : la signature ne correspond pas à cette clé publique" >&2
    echo "cette publication n'a pas été produite par le détenteur de la clé attendue" >&2
    exit 1
fi
echo "✓ signature valide"

if ! (cd "$artefacts" && sha256sum --quiet --check SHA256SUMS); then
    echo "ÉCHEC : un fichier ne correspond pas à son empreinte signée" >&2
    exit 1
fi
echo "✓ empreintes conformes"

echo
echo "environnement de construction déclaré :"
sed 's/^/    /' "$artefacts/BUILD-INFO"
echo
echo "Pour établir que ce binaire correspond bien au code, le reconstruire depuis le commit"
echo "ci-dessus avec les mêmes versions d'outillage, puis comparer les empreintes."
