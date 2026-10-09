#!/bin/sh
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Verifie commun.sh : la citation des arguments, et les valeurs exigees.
#
# ssh ne transporte pas une liste d arguments mais une ligne de commande : un
# jsonpath mal cite arrive tronque au shell distant, qui refuse la commande ou,
# pire, en joue une autre.
#
# Le shell distant est ici un sh local et un faux kubectl qui recrache ce qu il
# recoit, un argument par ligne : ce qui ressort doit etre ce qui est entre.
set -eu

ici="$(cd "$(dirname "$0")" && pwd)"
racine="$(cd "$ici/.." && pwd)"
. "$racine/commun.sh"

atelier="$(mktemp -d)"
trap 'rm -rf "$atelier"' EXIT INT TERM
printf '#!/bin/sh\nfor a in "$@"; do printf "%%s\\n" "$a"; done\n' > "$atelier/kubectl"
chmod 755 "$atelier/kubectl"

. "$ici/cas.sh"

# Fait traverser un shell aux arguments, comme ssh le ferait, et les rend.
aller_retour() {
    PATH="$atelier:$PATH" sh -c "kubectl$(citer "$@")"
}

cas() {
    enonce "$1"; shift
    attendu="$(for a in "$@"; do printf '%s\n' "$a"; done)"
    obtenu="$(aller_retour "$@")"
    if [ "$obtenu" = "$attendu" ]; then
        echo ok; reussis=$((reussis + 1))
    else
        echo "ECHEC"; echoues=$((echoues + 1))
        printf '      attendu : %s\n      obtenu  : %s\n' \
            "$(printf '%s' "$attendu" | tr '\n' '|')" "$(printf '%s' "$obtenu" | tr '\n' '|')"
    fi
}

cas "un jsonpath garde ses parentheses et ses guillemets" \
    get pods -o 'jsonpath={.items[0].spec.containers[?(@.name=="prometheus")].image}'
cas "un argument a espaces reste un seul argument" \
    get pods -l 'app = freeipa'
cas "une apostrophe ne termine pas la citation" \
    annotate pod "note=aujourd'hui"
cas "un dollar n est pas developpe par le shell distant" \
    get pods -o 'jsonpath=${.metadata.name}'
cas "un point-virgule ne devient pas une seconde commande" \
    get 'pods; echo intrus'
cas "une apostrophe inverse n ouvre pas de sous-commande" \
    get 'pods`echo intrus`'
cas "un argument vide est transmis comme tel" \
    get pods ""

echo
echo "  charger_configuration"

# Chaque cas a sa propre configuration : jamais celle du poste. Le sous-shell
# contient le exit 2, et $1 n est pas cite pour pouvoir exiger plusieurs noms.
charger() {
    ( CONFIGURATION="$atelier/configuration.env" \
      charger_configuration "$racine" $1 2>"$atelier/err" )
}

printf 'FICHIER_METRIQUES=/var/lib/node_exporter/textfile_collector/freeipa.prom\nNAMESPACE=\n' \
    > "$atelier/configuration.env"

enonce "qui ne gere que ses hotes se charge sans aucune valeur de cluster"
if charger FICHIER_METRIQUES; then
    reussi
else
    echoue "$(cat "$atelier/err")"
fi

enonce "n exiger aucun nom charge le fichier quoi qu il y manque"
if charger ""; then
    reussi
else
    echoue "$(cat "$atelier/err")"
fi

enonce "une valeur exigee mais vide arrete le script et se fait nommer"
if charger NAMESPACE; then
    echoue "le chargement a reussi avec un namespace vide"
elif grep -q 'NAMESPACE n est pas renseigne' "$atelier/err"; then
    reussi
else
    echoue "$(cat "$atelier/err")"
fi

enonce "un nom absent du fichier est traite comme une valeur vide"
if charger "FICHIER_METRIQUES SELECTEUR_PROMETHEUS"; then
    echoue "le chargement a reussi alors que le nom n est pas dans le fichier"
elif grep -q 'SELECTEUR_PROMETHEUS n est pas renseigne' "$atelier/err"; then
    reussi
else
    echoue "$(cat "$atelier/err")"
fi

enonce "les valeurs sont exportees, sinon rendre.sh ne les verrait pas"
obtenu=$(CONFIGURATION="$atelier/configuration.env" sh -c \
    ". $racine/commun.sh; charger_configuration $racine; sh -c \"printf %s \\\$FICHIER_METRIQUES\"" 2>/dev/null)
if [ "$obtenu" = /var/lib/node_exporter/textfile_collector/freeipa.prom ]; then
    reussi
else
    echoue "un sous-processus a lu : $obtenu"
fi

enonce "une configuration absente donne la commande qui la cree"
rm -f "$atelier/configuration.env"
if charger FICHIER_METRIQUES; then
    echoue "le chargement a reussi sans fichier"
elif grep -q 'configuration absente' "$atelier/err" \
     && grep -q 'cp .*configuration.env.exemple' "$atelier/err"; then
    reussi
else
    echoue "$(cat "$atelier/err")"
fi

bilan
