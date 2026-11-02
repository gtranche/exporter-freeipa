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
. "$ici/cas.sh"

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

# La detection de node_exporter, jouee sur un faux /proc : la machine qui joue
# le banc n a ni /proc ni « stat -c ». Le faux pgrep applique le motif recu a
# la ligne de commande simulee, exactement comme « pgrep -f » : c est donc bien
# le motif de l installeur qui est eprouve, et non une imitation complaisante.
decor="$atelier/detection"
mkdir -p "$decor/bin"
cat > "$decor/bin/pgrep" <<'EOF'
#!/bin/sh
[ "$1" = "-f" ] || exit 2
printf '%s\n' "$CMDLINE_SIMULEE" | grep -Eq -- "$2" || exit 1
echo 4242
EOF
cat > "$decor/bin/stat" <<'EOF'
#!/bin/sh
printf '%s\n' "$PROPRIETAIRE_SIMULE"
EOF
chmod +x "$decor/bin/pgrep" "$decor/bin/stat"

# Le vrai /proc separe les arguments par des octets nuls ET en pose un apres le
# dernier : sans lui, « read » perd l argument de queue, qui est le drapeau.
diagnostiquer() {
    rm -rf "$decor/proc"
    mkdir -p "$decor/proc/4242"
    printf '%s ' "$1" | tr ' ' '\0' > "$decor/proc/4242/cmdline"
    CMDLINE_SIMULEE="$1" PROPRIETAIRE_SIMULE="$2" RACINE_PROC="$decor/proc" \
        PATH="$decor/bin:$PATH" "$racine/installer.sh" --racine "$cible" --repertoire-servi
}

enonce "le repertoire servi est trouve bien que le binaire porte le nom du paquet"
# Mesure du 2026-11-01 sur freeipa : le processus s appelle
# prometheus-node-exporter, tronque a prometheus-node, et l ancien
# « pgrep -x node_exporter » ne rendait rien.
if obtenu=$(diagnostiquer \
      "/usr/bin/prometheus-node-exporter --collector.textfile.directory=/var/lib/node_exporter/textfile_collector" \
      root 2>&1) \
   && [ "${obtenu##*
}" = /var/lib/node_exporter/textfile_collector ]; then
    reussi
else
    echoue "${obtenu:-aucun repertoire rendu}"
fi

enonce "le binaire pose a la main, nomme node_exporter, est trouve aussi"
if obtenu=$(diagnostiquer \
      "/usr/local/bin/node_exporter --collector.textfile.directory=/srv/textfile" root 2>&1) \
   && [ "${obtenu##*
}" = /srv/textfile ]; then
    reussi
else
    echoue "${obtenu:-aucun repertoire rendu}"
fi

enonce "le drapeau separe de sa valeur est lu comme celui qui porte un egal"
if obtenu=$(diagnostiquer \
      "/usr/bin/node_exporter --collector.textfile.directory /srv/ailleurs" root 2>&1) \
   && [ "${obtenu##*
}" = /srv/ailleurs ]; then
    reussi
else
    echoue "${obtenu:-aucun repertoire rendu}"
fi

enonce "un node_exporter d un compte non privilegie ne designe aucun repertoire"
if obtenu=$(diagnostiquer \
      "/tmp/node_exporter --collector.textfile.directory=/tmp/a_moi" mallory 2>&1); then
    echoue "le repertoire de mallory a ete retenu : $obtenu"
elif printf '%s' "$obtenu" | grep -q "compte non privilegie"; then
    reussi
else
    echoue "$obtenu"
fi

enonce "un nom qui ressemble sans en etre un n est pas pris pour node_exporter"
if obtenu=$(diagnostiquer \
      "/usr/local/bin/node_exporter_bidon --collector.textfile.directory=/tmp/bidon" root 2>&1); then
    echoue "le faux a ete retenu : $obtenu"
else
    reussi
fi

enonce "un node_exporter sans le drapeau ne fait pas croire que le fichier sera lu"
if obtenu=$(diagnostiquer "/usr/bin/node_exporter --web.listen-address=:9100" root 2>&1); then
    echoue "un repertoire a ete rendu : $obtenu"
elif printf '%s' "$obtenu" | grep -q "aucun node_exporter"; then
    reussi
else
    echoue "$obtenu"
fi

enonce "sans aucun node_exporter, le diagnostic refuse au lieu de rendre un defaut"
if obtenu=$(diagnostiquer "/usr/sbin/sshd -D" root 2>&1); then
    echoue "un repertoire a ete rendu : $obtenu"
elif printf '%s' "$obtenu" | grep -q "aucun node_exporter"; then
    reussi
else
    echoue "$obtenu"
fi

bilan
