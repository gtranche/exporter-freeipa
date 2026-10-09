#!/bin/sh
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Rend le manifeste et l applique : Service, Endpoints, ServiceMonitor et les
# quinze alertes. Idempotent.
#
# Voie optionnelle : elle suppose un acces kubectl au cluster. Qui ne l a pas
# remet le fichier rendu par rendre.sh a qui gere Prometheus.
set -eu

ici="$(cd "$(dirname "$0")" && pwd)"
. "$ici/commun.sh"
charger_configuration "$ici" NAMESPACE

"$ici/rendre.sh" "$ici/kubernetes/supervision.yaml.modele" | kube_entree apply -f -
