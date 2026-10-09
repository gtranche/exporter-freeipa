#!/usr/bin/env bash
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Pose le tableau Grafana : ConfigMap + volume + montage dans le Deployment.
#
# Grafana ne decouvre rien tout seul : chaque tableau est un volume explicite
# monte sous $RACINE_TABLEAUX/<nom>, que le fournisseur de provisionnement lit
# de maniere recursive. Ajouter le tableau fait donc redemarrer Grafana — une
# fois, et seulement si le montage manquait.
set -euo pipefail

ICI="$(cd "$(dirname "$0")" && pwd)"
RACINE="$(cd "$ICI/.." && pwd)"
. "$RACINE/commun.sh"
charger_configuration "$RACINE"

NOM=freeipa
FICHIER="$ICI/tableau-${NOM}.json"
CM="grafana-dashboard-${NOM}"
MONTAGE="${RACINE_TABLEAUX%/}/${NOM}"

[ -f "$FICHIER" ] || { echo "$FICHIER introuvable" >&2; exit 1; }

# Un JSON invalide se traduirait par un tableau vide dans l interface, sans
# aucun message : on refuse avant d envoyer.
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$FICHIER" \
    || { echo "$FICHIER n est pas un JSON valide" >&2; exit 1; }

# Le ConfigMap est bati ici, pas par un kubectl distant : rien n est depose
# dans le /tmp de l hote, et un seul flux traverse la connexion.
echo "== ConfigMap $CM dans $NAMESPACE =="
python3 - "$FICHIER" "$CM" "$NAMESPACE" "$NOM" <<'PY' | kube_entree apply -f -
import json, sys

fichier, nom_cm, namespace, nom = sys.argv[1:5]
print(json.dumps({
    "apiVersion": "v1", "kind": "ConfigMap",
    "metadata": {"name": nom_cm, "namespace": namespace},
    "data": {f"{nom}.json": open(fichier, encoding="utf-8").read()},
}))
PY

if kube get deploy "$DEPLOIEMENT_GRAFANA" \
     -o jsonpath='{.spec.template.spec.volumes[*].name}' | tr ' ' '\n' | grep -qx "$CM"; then
    echo "== montage deja present, Grafana n est pas redemarre =="
else
    echo "== ajout du volume et du montage =="
    kube patch deploy "$DEPLOIEMENT_GRAFANA" --type=strategic -p "$(cat <<JSON
{"spec": {"template": {"spec": {
  "volumes": [{"name": "$CM", "configMap": {"name": "$CM"}}],
  "containers": [{"name": "grafana",
    "volumeMounts": [{"name": "$CM", "mountPath": "$MONTAGE"}]}]}}}}
JSON
)"
    kube rollout status "deploy/$DEPLOIEMENT_GRAFANA" --timeout=180s
fi

# Verifier l effet, pas la commande : un patch accepte n est pas un fichier lu.
echo "== verification dans le conteneur =="
# Viser le deploiement, pas un nom de pod releve a la main : kubectl choisit
# alors un pod pret et vivant, et non celui qui s eteint apres le rollout.
kube exec "deploy/$DEPLOIEMENT_GRAFANA" -c grafana -- ls -l "$MONTAGE"
