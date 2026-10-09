#!/bin/sh
# Verifie la citation des arguments. ssh ne transporte pas une liste
# d arguments mais une ligne de commande : un jsonpath mal cite arrive
# tronque au shell distant, qui refuse la commande ou, pire, en joue une autre.
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

reussis=0
echoues=0

# Fait traverser un shell aux arguments, comme ssh le ferait, et les rend.
aller_retour() {
    PATH="$atelier:$PATH" sh -c "kubectl$(citer "$@")"
}

cas() {
    enonce="$1"; shift
    printf '  %-70s ' "$enonce"
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
echo "$reussis reussi(s), $echoues echec(s)."
[ "$echoues" -eq 0 ]
