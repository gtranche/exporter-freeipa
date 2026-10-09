#!/bin/sh
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Joue les tests unitaires des alertes avec promtool, sur les regles RENDUES :
# ce sont celles qui seront appliquees, pas le modele.
#
# promtool ne se distribue pas seul : on l emprunte a une image Prometheus,
# dans un conteneur jetable. Jamais dans le pod Prometheus en place — sa racine
# est en lecture seule, ce qui fait paniquer promtool sans message utile, et sa
# limite memoire est calibree pour Prometheus, pas pour un outil de plus.
set -eu

ici="$(cd "$(dirname "$0")" && pwd)"
racine="$(cd "$ici/.." && pwd)"
. "$racine/commun.sh"
charger_configuration "$racine"

moteur="${MOTEUR_CONTENEUR:-podman}"
atelier="$(mktemp -d)"
distant="/tmp/essai-alertes-freeipa-$$"
nettoyer() {
    rm -rf "$atelier"
    [ -n "${HOTE_KUBECTL:-}" ] && ssh -n ${SSH_OPTS_KUBECTL:-} "$HOTE_KUBECTL" "rm -rf $distant" >/dev/null 2>&1
    true
}
trap nettoyer EXIT INT TERM

"$racine/rendre.sh" "$racine/kubernetes/supervision.yaml.modele" > "$atelier/manifeste-rendu.yaml"
"$racine/rendre.sh" "$ici/test-alertes-freeipa.yaml.modele" > "$atelier/test-alertes-freeipa.yaml"

# Les annotations sont retirees : promtool exige une egalite exacte sur elles,
# et ces tests protegent le declenchement, pas la redaction des messages.
python3 - "$atelier/manifeste-rendu.yaml" > "$atelier/regles-extraites.yaml" <<'PY'
import sys, yaml

spec = None
for doc in yaml.safe_load_all(open(sys.argv[1])):
    if doc and doc.get("kind") == "PrometheusRule":
        if spec is not None:
            sys.exit("plusieurs PrometheusRule dans le fichier : lequel tester ?")
        spec = doc["spec"]
if spec is None:
    sys.exit("aucun PrometheusRule trouve")

for groupe in spec["groups"]:
    for regle in groupe["rules"]:
        regle.pop("annotations", None)

print(yaml.safe_dump(spec, sort_keys=False, allow_unicode=True), end="")
PY

echo "Regles extraites : $(grep -c '^  *- alert:' "$atelier/regles-extraites.yaml") alertes."

# La meme version que celle qui evaluera ces regles pour de vrai.
image="${IMAGE_PROMETHEUS:-}"
if [ -z "$image" ]; then
    : "${NAMESPACE:?NAMESPACE est exige pour relever l image du cluster, ou renseignez IMAGE_PROMETHEUS pour jouer les tests sans cluster}"
    image=$(kube get pods -l app.kubernetes.io/name=prometheus \
        -o jsonpath='{.items[0].spec.containers[?(@.name=="prometheus")].image}')
    [ -n "$image" ] || { echo "aucun pod Prometheus trouve : renseignez IMAGE_PROMETHEUS" >&2; exit 2; }
fi
echo "promtool emprunte a : $image"

if [ -n "${HOTE_KUBECTL:-}" ]; then
    ssh -n ${SSH_OPTS_KUBECTL:-} "$HOTE_KUBECTL" "mkdir -p $distant"
    # tar de macOS joint des attributs etendus que tar de GNU signale a
    # l extraction. Les options qui les taisent lui sont inconnues : on essaie.
    opts_tar=""
    if tar --no-xattrs --no-mac-metadata -cf /dev/null -C "$atelier" \
           regles-extraites.yaml 2>/dev/null; then
        opts_tar="--no-xattrs --no-mac-metadata"
    fi
    tar $opts_tar -C "$atelier" -cf - regles-extraites.yaml test-alertes-freeipa.yaml \
      | ssh ${SSH_OPTS_KUBECTL:-} "$HOTE_KUBECTL" "tar -C $distant -xf -"
    ssh -n ${SSH_OPTS_KUBECTL:-} "$HOTE_KUBECTL" \
        "$moteur image inspect '$image' >/dev/null 2>&1 || $moteur pull -q '$image' >/dev/null"
    jouer() {
        ssh -n ${SSH_OPTS_KUBECTL:-} "$HOTE_KUBECTL" "$moteur run --rm --network=none \
            -v $distant:/essai:Z -w /essai --entrypoint=/bin/promtool '$image' $*"
    }
else
    "$moteur" image inspect "$image" >/dev/null 2>&1 || "$moteur" pull -q "$image" >/dev/null
    jouer() {
        "$moteur" run --rm --network=none -v "$atelier":/essai:Z -w /essai \
            --entrypoint=/bin/promtool "$image" "$@"
    }
fi

echo "--- promtool check rules"
jouer check rules regles-extraites.yaml
echo "--- promtool test rules"
jouer test rules test-alertes-freeipa.yaml
