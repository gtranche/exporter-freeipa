# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Charge la configuration et joue kubectl la ou il faut. A sourcer, pas a jouer.

# Les noms exiges sont ceux que le script appelant emploie, et eux seuls :
# reclamer les valeurs du cluster a qui ne gere que ses hotes FreeIPA lui
# ferait renseigner un namespace dont il n a que faire.
#   charger_configuration "$ici" NAMESPACE
charger_configuration() {
    racine="$1"
    shift
    fichier="${CONFIGURATION:-$racine/configuration.env}"
    if [ ! -f "$fichier" ]; then
        echo "configuration absente : $fichier" >&2
        echo "  cp $racine/configuration.env.exemple $racine/configuration.env" >&2
        exit 2
    fi
    # Exportees : rendre.sh les lit depuis l environnement d un sous-processus.
    set -a
    . "$fichier"
    set +a
    for nom in "$@"; do
        eval "valeur=\${$nom:-}"
        [ -n "$valeur" ] || { echo "$nom n est pas renseigne dans $fichier" >&2; exit 2; }
    done
}

# ssh ne transporte pas une liste d arguments mais une ligne de commande : sans
# citation, un jsonpath perd ses parentheses et ses guillemets en route.
citer() {
    rendu=""
    for a in "$@"; do
        a=$(printf '%s' "$a" | sed "s/'/'\\\\''/g")
        rendu="$rendu '$a'"
    done
    printf '%s' "$rendu"
}

# kubectl local par defaut : exiger un rebond ssh serait un choix de site.
kube() {
    if [ -n "${HOTE_KUBECTL:-}" ]; then
        ssh -n ${SSH_OPTS_KUBECTL:-} "$HOTE_KUBECTL" \
            "kubectl -n $(citer "$NAMESPACE")$(citer "$@")"
    else
        kubectl -n "$NAMESPACE" "$@"
    fi
}

# ssh -n ferme l entree standard : les commandes qui lisent un flux passent ici.
kube_entree() {
    if [ -n "${HOTE_KUBECTL:-}" ]; then
        ssh ${SSH_OPTS_KUBECTL:-} "$HOTE_KUBECTL" \
            "kubectl -n $(citer "$NAMESPACE")$(citer "$@")"
    else
        kubectl -n "$NAMESPACE" "$@"
    fi
}
