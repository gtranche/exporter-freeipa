#!/bin/sh
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Rend le manifeste et l applique : Service, Endpoints, ServiceMonitor et les
# neuf alertes. Idempotent.
set -eu

ici="$(cd "$(dirname "$0")" && pwd)"
. "$ici/commun.sh"
charger_configuration "$ici"

"$ici/rendre.sh" "$ici/kubernetes/supervision.yaml.modele" | kube_entree apply -f -
