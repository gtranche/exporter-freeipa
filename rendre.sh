#!/bin/sh
# Remplace les @MARQUEURS@ d un modele par les valeurs de configuration.env, et
# ecrit le resultat sur la sortie standard.
#
#     ./rendre.sh kubernetes/supervision.yaml.modele | kubectl apply -f -
#
# Un marqueur sans valeur fait echouer : un manifeste a moitie rendu
# s appliquerait sans erreur et superviserait la mauvaise machine.
set -eu

ici="$(cd "$(dirname "$0")" && pwd)"
. "$ici/commun.sh"
charger_configuration "$ici"

modele="${1:?chemin du modele}"
[ -f "$modele" ] || { echo "modele introuvable : $modele" >&2; exit 2; }

python3 - "$modele" <<'PY'
import os, re, sys

modele = open(sys.argv[1], encoding="utf-8").read()
manquants = set()


def valeur(m):
    nom = m.group(1)
    v = os.environ.get(nom)
    if not v:
        manquants.add(nom)
        return m.group(0)
    return v


rendu = re.sub(r"@([A-Z_][A-Z0-9_]*)@", valeur, modele)
if manquants:
    sys.exit("sans valeur dans configuration.env : " + ", ".join(sorted(manquants)))
sys.stdout.write(rendu)
PY
