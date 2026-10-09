#!/bin/sh
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Joue les suites. Les six premieres ne demandent rien ; la derniere veut un
# moteur de conteneurs, et un cluster si IMAGE_PROMETHEUS est vide.
#
# SANS_ALERTES=1 saute la derniere, pour qui veut seulement lire le code.
set -eu
ici="$(cd "$(dirname "$0")" && pwd)"

echo "===== exportateur"
python3 "$ici/tests/test-exporter-freeipa.py"

echo
echo "===== tableau"
python3 "$ici/tests/test-tableau.py"

echo
echo "===== depot publiable"
python3 "$ici/tests/test-depot-public.py"

echo
echo "===== citation des arguments distants"
"$ici/tests/test-commun.sh"

echo
echo "===== rendu des modeles"
"$ici/tests/test-rendu.sh"

echo
echo "===== pose et retrait"
"$ici/tests/test-installer.sh"

echo
echo "===== alertes"
if [ "${SANS_ALERTES:-}" = 1 ]; then
    echo "sautees : SANS_ALERTES=1"
else
    "$ici/tests/tester-alertes.sh" "$@"
fi
