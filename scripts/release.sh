#!/usr/bin/env bash
#
# Construit une publication vérifiable de l'application de bureau, et la signe.
#
# # Reproductible d'abord, signé ensuite
#
# Une signature dit « quelqu'un détenant cette clé a produit ce fichier ». Elle ne dit pas « ce
# fichier correspond à ce code ». Pour un projet dont la thèse est que l'utilisateur ne devrait
# pas avoir à croire l'opérateur sur parole, l'ordre importe : un binaire reproductible se
# vérifie en le reconstruisant, sans faire confiance à personne. La signature n'authentifie
# ensuite que la publication.
#
# # Pourquoi les préfixes sont calculés et non écrits dans `.cargo/config.toml`
#
# Sans `--remap-path-prefix`, le binaire contient le chemin absolu du répertoire de construction
# — 217 occurrences, mesurées avant ce script. Deux constructions honnêtes du même commit, sur
# deux machines, donnent alors deux empreintes différentes.
#
# Les écrire en dur dans un fichier de configuration versionné reproduirait le défaut qu'ils
# corrigent : ils ne vaudraient que pour la machine de celui qui les a écrits. Ils sont donc
# dérivés ici de `git rev-parse` et de `CARGO_HOME`.
#
# Les deux préfixes comptent. Celui du dépôt efface les chemins de notre code ; celui du registre
# efface ceux des dépendances, qui vivent sous `CARGO_HOME` et varient avec l'utilisateur.
# Oublier le second laisse une reproductibilité fausse de façon discrète : elle tient sur une même
# machine et casse ailleurs — c'est-à-dire au seul moment où elle sert.
#
# # Usage
#
#   scripts/release.sh /chemin/vers/cle-privee.pem
#   RELEASE_KEY=/chemin/vers/cle-privee.pem scripts/release.sh
#
# La clé privée n'est jamais lue depuis le dépôt et n'y entre jamais. Pour en créer une :
#
#   openssl genpkey -algorithm ed25519 -out cle-privee.pem
#   openssl pkey -in cle-privee.pem -pubout -out release/whatsapp_clone.pub
set -euo pipefail

racine="$(git rev-parse --show-toplevel)"
cd "$racine"

cle="${1:-${RELEASE_KEY:-}}"
if [[ -z "$cle" ]]; then
    echo "erreur : chemin de la clé privée manquant (argument ou RELEASE_KEY)" >&2
    echo "voir l'en-tête de ce script pour en produire une" >&2
    exit 1
fi
if [[ ! -r "$cle" ]]; then
    echo "erreur : clé privée illisible : $cle" >&2
    exit 1
fi

# Une publication dont le contenu ne correspond à aucun commit n'est pas vérifiable : personne ne
# saurait quoi reconstruire pour la comparer. C'est le genre d'erreur qui ne se remarque
# qu'après distribution, donc on refuse avant.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "erreur : l'arbre de travail contient des modifications non validées" >&2
    echo "une publication doit correspondre exactement à un commit" >&2
    exit 1
fi

commit="$(git rev-parse HEAD)"

# Neutralise les horodatages de construction. La date du commit plutôt que l'heure courante :
# elle est la même pour tous ceux qui reconstruiront ce commit.
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export SOURCE_DATE_EPOCH

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$racine=/build --remap-path-prefix=$cargo_home/registry=/cargo-registry"

sortie="$racine/release/artefacts"
rm -rf "$sortie"
mkdir -p "$sortie"

echo "→ construction de l'interface"
(cd apps/web && pnpm install --frozen-lockfile && pnpm run build)

echo "→ construction du binaire"
cargo build -p desktop --release

cp target/release/desktop "$sortie/whatsapp_clone"

# Les versions font partie de la publication, pas de la documentation. La reproductibilité vaut
# **à environnement donné** : une autre version de `rustc` ou de `pnpm` produit un binaire
# différent sans que rien ne soit compromis. Sans ce fichier, celui qui vérifie ne peut pas
# distinguer une altération d'un simple écart d'outillage — et apprend à ignorer l'échec.
cat > "$sortie/BUILD-INFO" <<INFO
commit=$commit
source_date_epoch=$SOURCE_DATE_EPOCH
rustc=$(rustc --version)
cargo=$(cargo --version)
node=$(node --version)
pnpm=$(pnpm --version)
INFO

echo "→ empreintes et signature"
(cd "$sortie" && sha256sum whatsapp_clone BUILD-INFO > SHA256SUMS)

# La signature porte sur `SHA256SUMS`, pas sur le binaire : un seul fichier signé couvre ainsi
# l'ensemble de la publication, y compris `BUILD-INFO`. Signer le binaire seul laisserait les
# versions d'outillage modifiables sans que la signature en souffre.
openssl pkeyutl -sign -rawin -inkey "$cle" \
    -in "$sortie/SHA256SUMS" -out "$sortie/SHA256SUMS.sig"

echo
echo "publication prête dans release/artefacts :"
ls -1 "$sortie"
echo
echo "à vérifier avec : scripts/verify-release.sh"
