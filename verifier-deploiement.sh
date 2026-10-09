#!/usr/bin/env bash
# Confronte ce depot a ce qui tourne reellement sur la machine FreeIPA.
# Ne modifie rien : il lit, compare, et sort en 1 s il y a le moindre ecart.
#
# La cible ssh, les chemins et le reste viennent de configuration.env ; un
# argument les emporte sur la cible, pour verifier un second serveur.
#
#     ./verifier-deploiement.sh [cible-ssh]
set -uo pipefail

ICI="$(cd "$(dirname "$0")" && pwd)"
. "$ICI/commun.sh"
charger_configuration "$ICI"

CIBLE=${1:-${CIBLE_SSH:?CIBLE_SSH n est pas renseigne dans configuration.env}}
PROM=${FICHIER_METRIQUES:?FICHIER_METRIQUES n est pas renseigne}
ecarts=0

dire() { printf '%-52s %s\n' "$1" "$2"; }
echouer() { dire "$1" "ECART : $2"; ecarts=$((ecarts + 1)); }

distant() { ssh -n ${SSH_OPTS_FREEIPA:-} "$CIBLE" "$1" 2>/dev/null; }

# Une seule connexion pour tout relever : le reste se compare en local.
releve=$(distant "
  { sha256sum /usr/local/bin/exporter-freeipa.py 2>/dev/null \
    || shasum -a 256 /usr/local/bin/exporter-freeipa.py 2>/dev/null; } | cut -d' ' -f1
  echo ---
  cat /etc/systemd/system/exporter-freeipa.service 2>/dev/null
  echo ---
  cat /etc/systemd/system/exporter-freeipa.timer 2>/dev/null
  echo ---
  systemctl is-enabled exporter-freeipa.timer 2>/dev/null
  systemctl is-active exporter-freeipa.timer 2>/dev/null
  echo ---
  stat -c %Y $PROM 2>/dev/null
  date +%s
  echo ---
  grep -c '^freeipa_' $PROM 2>/dev/null
  grep '^freeipa_collecte_reussie ' $PROM 2>/dev/null
")
[ -z "$releve" ] && { echo "aucune reponse de $CIBLE" >&2; exit 2; }

lot() { awk -v n="$1" 'BEGIN{b=1} /^---$/{b++; next} b==n' <<< "$releve"; }

# sha256sum sous Linux, shasum sous macOS : ce script se joue des deux cotes.
empreinte_locale=$({ sha256sum "$ICI/exporter-freeipa.py" 2>/dev/null \
    || shasum -a 256 "$ICI/exporter-freeipa.py" 2>/dev/null; } | cut -d' ' -f1)
empreinte_distante=$(lot 1 | tr -d '[:space:]')
if [ -z "$empreinte_distante" ]; then
    echouer "exportateur en place" "/usr/local/bin/exporter-freeipa.py absent"
elif [ "$empreinte_locale" = "$empreinte_distante" ]; then
    dire "exportateur identique au depot" "oui (${empreinte_locale:0:12})"
else
    echouer "exportateur identique au depot" "empreintes differentes (${empreinte_locale:0:12} vs ${empreinte_distante:0:12})"
fi

for n in 2 3; do
    case $n in
      2) nom=exporter-freeipa.service ;;
      3) nom=exporter-freeipa.timer ;;
    esac
    # Les commentaires du depot ne sont pas un ecart de comportement : systemd
    # ne les lit pas. On compare les directives seules.
    directives() { grep -vE '^\s*(#|;|$)' "$1" | sed 's/[[:space:]]*$//'; }
    if diff -q <(directives "$ICI/systemd/$nom") <(lot "$n" | grep -vE '^\s*(#|;|$)' | sed 's/[[:space:]]*$//') >/dev/null; then
        dire "$nom conforme au depot" "oui"
    else
        echouer "$nom conforme au depot" "les directives divergent"
    fi
done

etat=$(lot 4)
[ "$(sed -n 1p <<< "$etat")" = enabled ] \
  && dire "minuteur active au demarrage" "oui" \
  || echouer "minuteur active au demarrage" "is-enabled = $(sed -n 1p <<< "$etat")"
[ "$(sed -n 2p <<< "$etat")" = active ] \
  && dire "minuteur en marche" "oui" \
  || echouer "minuteur en marche" "is-active = $(sed -n 2p <<< "$etat")"

dates=$(lot 5)
mtime=$(sed -n 1p <<< "$dates"); maintenant=$(sed -n 2p <<< "$dates")
if [ -z "$mtime" ]; then
    echouer "fichier de metriques" "$PROM absent"
else
    age=$((maintenant - mtime))
    # Le minuteur passe toutes les minutes : au-dela de 5 minutes la collecte
    # ne tourne plus, meme si le fichier existe et se lit normalement.
    [ "$age" -lt 300 ] \
      && dire "collecte fraiche" "${age}s" \
      || echouer "collecte fraiche" "le fichier a ${age}s"
fi

contenu=$(lot 6)
series=$(sed -n 1p <<< "$contenu")
[ "${series:-0}" -gt 100 ] \
  && dire "series exposees" "$series" \
  || echouer "series exposees" "seulement ${series:-0}"
[ "$(sed -n 2p <<< "$contenu")" = "freeipa_collecte_reussie 1" ] \
  && dire "derniere collecte complete" "oui" \
  || echouer "derniere collecte complete" "$(sed -n 2p <<< "$contenu")"

echo
[ "$ecarts" -eq 0 ] && { echo "Aucun ecart."; exit 0; }
echo "$ecarts ecart(s)."
exit 1
