#!/bin/sh
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Verifie la pose et le retrait sans toucher a la machine : tout se joue dans
# une racine jetable, celle que --racine sert a preparer.
set -eu

ici="$(cd "$(dirname "$0")" && pwd)"
racine="$(cd "$ici/.." && pwd)"
atelier="$(mktemp -d)"
trap 'rm -rf "$atelier"' EXIT INT TERM
reussis=0
echoues=0

enonce() { printf '  %-72s ' "$1"; }
reussi() { echo ok; reussis=$((reussis + 1)); }
echoue() { echo "ECHEC : $1"; echoues=$((echoues + 1)); }

cible="$atelier/racine"
installer() { "$racine/installer.sh" --racine "$cible" "$@"; }

enonce "une pose prepare l exportateur, ses deux unites et le repertoire servi"
rm -rf "$cible"
if installer > "$atelier/pose" 2>&1 \
   && [ -f "$cible/usr/local/bin/exporter-freeipa.py" ] \
   && [ -f "$cible/etc/systemd/system/exporter-freeipa.service" ] \
   && [ -f "$cible/etc/systemd/system/exporter-freeipa.timer" ] \
   && [ -d "$cible/var/lib/node_exporter/textfile_collector" ]; then
    reussi
else
    echoue "$(cat "$atelier/pose")"
fi

enonce "l exportateur est executable, les unites ne le sont pas"
if [ -x "$cible/usr/local/bin/exporter-freeipa.py" ] \
   && [ ! -x "$cible/etc/systemd/system/exporter-freeipa.service" ] \
   && [ ! -x "$cible/etc/systemd/system/exporter-freeipa.timer" ]; then
    reussi
else
    echoue "modes inattendus : $(ls -l "$cible/usr/local/bin/exporter-freeipa.py" "$cible/etc/systemd/system/")"
fi

enonce "l exportateur pose est bien celui du depot, octet pour octet"
if cmp -s "$racine/exporter-freeipa.py" "$cible/usr/local/bin/exporter-freeipa.py"; then
    reussi
else
    echoue "le fichier pose differe de la source"
fi

enonce "une seconde pose ne reecrit rien et le dit"
if installer > "$atelier/repose" 2>&1 \
   && [ "$(grep -c 'deja a jour' "$atelier/repose")" = 3 ]; then
    reussi
else
    echoue "$(cat "$atelier/repose")"
fi

enonce "une version plus recente de l exportateur remplace celle qui est posee"
echo "# modifie" >> "$cible/usr/local/bin/exporter-freeipa.py"
if installer > "$atelier/maj" 2>&1 \
   && cmp -s "$racine/exporter-freeipa.py" "$cible/usr/local/bin/exporter-freeipa.py" \
   && grep -q 'pose : /usr/local/bin/exporter-freeipa.py' "$atelier/maj"; then
    reussi
else
    echoue "$(cat "$atelier/maj")"
fi

enonce "le retrait enleve l exportateur et ses unites"
if installer --desinstaller > "$atelier/retrait" 2>&1 \
   && [ ! -e "$cible/usr/local/bin/exporter-freeipa.py" ] \
   && [ ! -e "$cible/etc/systemd/system/exporter-freeipa.service" ] \
   && [ ! -e "$cible/etc/systemd/system/exporter-freeipa.timer" ]; then
    reussi
else
    echoue "$(cat "$atelier/retrait")"
fi

enonce "le retrait emporte le fichier de metriques, que personne ne saurait perime"
rm -rf "$cible"
installer > /dev/null 2>&1
echo 'freeipa_collecte_reussie 1' > "$cible/var/lib/node_exporter/textfile_collector/freeipa.prom"
if installer --desinstaller > "$atelier/retrait2" 2>&1 \
   && [ ! -e "$cible/var/lib/node_exporter/textfile_collector/freeipa.prom" ]; then
    reussi
else
    echoue "$(cat "$atelier/retrait2")"
fi

enonce "le fichier de surcharge de l administrateur survit a la pose et au retrait"
rm -rf "$cible"
mkdir -p "$cible/etc/sysconfig"
printf 'INSTANCE_DIRSRV=IMPOSE\n' > "$cible/etc/sysconfig/exporter-freeipa"
installer > /dev/null 2>&1
installer --desinstaller > /dev/null 2>&1
if [ "$(cat "$cible/etc/sysconfig/exporter-freeipa")" = "INSTANCE_DIRSRV=IMPOSE" ]; then
    reussi
else
    echoue "le fichier a ete reecrit : $(cat "$cible/etc/sysconfig/exporter-freeipa")"
fi

enonce "un retrait sur une racine vierge n echoue pas"
rm -rf "$cible"
mkdir -p "$cible"
if installer --desinstaller > "$atelier/vierge" 2>&1; then
    reussi
else
    echoue "$(cat "$atelier/vierge")"
fi

enonce "une machine qui n est pas un serveur FreeIPA est refusee avant toute ecriture"
if "$racine/installer.sh" > "$atelier/hors" 2>&1; then
    echoue "la pose a ete acceptee hors d un serveur FreeIPA"
elif grep -q "n est pas un serveur FreeIPA" "$atelier/hors"; then
    reussi
else
    echoue "$(cat "$atelier/hors")"
fi

enonce "le diagnostic ne pose rien, quel que soit son verdict"
rm -rf "$cible"
installer --repertoire-servi > "$atelier/diag" 2>&1 || true
if [ ! -e "$cible" ]; then
    reussi
else
    echoue "le diagnostic a ecrit : $(find "$cible" | head -3)"
fi

enonce "un argument inconnu arrete le script au lieu d etre ignore"
if installer --colleteur-textfile > "$atelier/inconnu" 2>&1; then
    echoue "l argument a ete ignore"
elif grep -q "argument inconnu" "$atelier/inconnu"; then
    reussi
else
    echoue "$(cat "$atelier/inconnu")"
fi

echo
echo "$reussis reussi(s), $echoues echec(s)."
[ "$echoues" -eq 0 ]
