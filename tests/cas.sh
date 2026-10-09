# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Le decor des suites en shell : un enonce par ligne, un compteur, un bilan qui
# vaut 1 des qu un cas tombe. A sourcer, pas a jouer.
#
# L enonce est une phrase : il dit l intention protegee, et c est lui qu on lit
# quand un cas tombe, avant d aller voir le code.

reussis=0
echoues=0

enonce() { printf '  %-72s ' "$1"; }
reussi() { echo ok; reussis=$((reussis + 1)); }
echoue() { echo "ECHEC : $1"; echoues=$((echoues + 1)); }

bilan() {
    echo
    echo "$reussis reussi(s), $echoues echec(s)."
    [ "$echoues" -eq 0 ]
}
