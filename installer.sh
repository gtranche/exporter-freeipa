#!/usr/bin/env bash
# Copyright (C) 2026 gtranche
# SPDX-License-Identifier: GPL-3.0-or-later
# Pose l exportateur sur un serveur FreeIPA existant, ou le retire.
#
# L installation ne sert a rien si node_exporter ne tourne pas avec
# --collector.textfile.directory : le fichier serait ecrit et personne ne le
# lirait. Le script le verifie, en deduit le repertoire a employer, et le dit.
#
# Usage : sudo ./installer.sh [--racine REP] [--desinstaller]
#         ./installer.sh --repertoire-servi   # ce que node_exporter sert, sans rien poser
#
# Sorties : 0 tout est en place ; 1 refus ou erreur ; 2 pose faite mais
# node_exporter ne servira pas le fichier.
set -euo pipefail

ICI="$(cd "$(dirname "$0")" && pwd)"
RACINE=""
ACTION=poser

BIN=/usr/local/bin/exporter-freeipa.py
UNITES=/etc/systemd/system
SYSCONFIG=/etc/sysconfig/exporter-freeipa
TEXTFILE_DEFAUT=/var/lib/node_exporter/textfile_collector

while [ $# -gt 0 ]; do
    case "$1" in
        --racine) RACINE="${2:?--racine attend un repertoire}"; shift 2 ;;
        --racine=*) RACINE="${1#*=}"; shift ;;
        --desinstaller) ACTION=retirer; shift ;;
        --repertoire-servi) ACTION=diagnostic; shift ;;
        -h|--help) awk 'NR>3 && /^#/ {sub(/^# ?/, ""); print; next} NR>3 {exit}' "$0"; exit 0 ;;
        *) echo "argument inconnu : $1" >&2; exit 1 ;;
    esac
done

# En mode --racine on prepare une arborescence (image, paquet, essai) : pas de
# machine a interroger, donc pas de systemd ni de collecte.
EN_PLACE=1
[ -n "$RACINE" ] && EN_PLACE=0

dit() { printf '%s\n' "$*"; }
refus() { printf '%s\n' "$*" >&2; exit 1; }

serveur_freeipa() {
    [ -f /etc/ipa/default.conf ] && { dit "serveur FreeIPA : /etc/ipa/default.conf"; return 0; }
    for c in /etc/dirsrv/slapd-*; do
        [ -d "$c" ] && { dit "instance 389-DS : $c"; return 0; }
    done
    for s in /run/slapd-*.socket; do
        [ -S "$s" ] && { dit "annuaire a l ecoute : $s"; return 0; }
    done
    return 1
}

outils_presents() {
    manquants=""
    for outil in python3 ldapsearch pgrep; do
        command -v "$outil" >/dev/null 2>&1 || manquants="$manquants $outil"
    done
    [ -z "$manquants" ] || refus "outils absents :$manquants (paquets python3, openldap-clients, procps-ng)"

    # curl et openssl ne servent qu a deux sondes : leur absence coute ces deux
    # mesures, pas la collecte.
    for outil in curl openssl ipactl; do
        command -v "$outil" >/dev/null 2>&1 \
            || dit "$outil absent : la sonde qui s en sert publiera un echec, les autres non."
    done
}

# Le repertoire que node_exporter sert vraiment, lu dans sa ligne de commande :
# l unite peut dire autre chose que le processus en cours.
COMPTES_SERVIS="root node_exporter node-exporter prometheus"

repertoire_servi() {
    local pid attendu mot proprietaire
    for pid in $(pgrep -x node_exporter 2>/dev/null || true); do
        [ -r "/proc/$pid/cmdline" ] || continue
        # Sans ce filtre, tout usager pourrait nommer un processus node_exporter
        # et designer le repertoire ou root ecrira.
        proprietaire=$(stat -c %U "/proc/$pid" 2>/dev/null || echo inconnu)
        case " $COMPTES_SERVIS " in
            *" $proprietaire "*) ;;
            *) dit "node_exporter de $proprietaire ignore : compte non privilegie." >&2; continue ;;
        esac
        attendu=0
        while IFS= read -r mot; do
            if [ "$attendu" = 1 ]; then printf '%s\n' "$mot"; return 0; fi
            case "$mot" in
                --collector.textfile.directory=*) printf '%s\n' "${mot#*=}"; return 0 ;;
                --collector.textfile.directory) attendu=1 ;;
            esac
        done < <(tr '\0' '\n' < "/proc/$pid/cmdline")
    done
    return 1
}

node_exporter_tourne() { pgrep -x node_exporter >/dev/null 2>&1; }

poser_fichier() {
    local source=$1 cible=$2 mode=$3
    [ -d "$(dirname "$cible")" ] || install -d -m 755 "$(dirname "$cible")"
    if [ -f "$cible" ] && cmp -s "$source" "$cible"; then
        dit "deja a jour : ${cible#"$RACINE"}"
        return 0
    fi
    install -m "$mode" "$source" "$cible"
    dit "pose : ${cible#"$RACINE"}"
}

poser() {
    local textfile=$TEXTFILE_DEFAUT

    if [ "$EN_PLACE" = 1 ]; then
        serveur_freeipa || refus "ce n est pas un serveur FreeIPA : ni /etc/ipa/default.conf, ni instance 389-DS, ni socket dans /run. Rien n a ete pose."
        [ "$(id -u)" = 0 ] || refus "a jouer en root : l exportateur, les unites et le repertoire de metriques sont hors de portee d un usager."
        outils_presents
        if servi=$(repertoire_servi); then
            textfile=$servi
            dit "node_exporter sert : $textfile"
        fi
    fi

    poser_fichier "$ICI/exporter-freeipa.py" "$RACINE$BIN" 755
    poser_fichier "$ICI/systemd/exporter-freeipa.service" "$RACINE$UNITES/exporter-freeipa.service" 644
    poser_fichier "$ICI/systemd/exporter-freeipa.timer" "$RACINE$UNITES/exporter-freeipa.timer" 644
    [ -d "$RACINE$textfile" ] || install -d -m 755 "$RACINE$textfile"
    dit "repertoire de metriques : $textfile"

    # Le fichier de surcharge appartient a l administrateur : on ne l ecrase
    # jamais, meme si le repertoire servi a change.
    if [ "$textfile" != "$TEXTFILE_DEFAUT" ]; then
        if [ -f "$RACINE$SYSCONFIG" ]; then
            dit "$SYSCONFIG existe : laisse tel quel, verifier FICHIER_METRIQUES=$textfile/freeipa.prom"
        else
            [ -d "$RACINE$(dirname "$SYSCONFIG")" ] || install -d -m 755 "$RACINE$(dirname "$SYSCONFIG")"
            printf 'FICHIER_METRIQUES=%s/freeipa.prom\n' "$textfile" > "$RACINE$SYSCONFIG"
            chmod 644 "$RACINE$SYSCONFIG"
            dit "ecrit : $SYSCONFIG"
        fi
    fi

    if [ "$EN_PLACE" = 0 ]; then
        dit "arborescence prete sous $RACINE ; ni systemd ni collecte en mode --racine."
        return 0
    fi

    systemctl daemon-reload
    systemctl enable --now exporter-freeipa.timer
    dit "minuteur : $(systemctl is-enabled exporter-freeipa.timer), $(systemctl is-active exporter-freeipa.timer)"

    collecter "$textfile"
}

collecter() {
    local textfile=$1 fichier series reussie surcharge
    fichier="$textfile/freeipa.prom"
    if [ -f "$RACINE$SYSCONFIG" ]; then
        surcharge=$(sed -n 's/^[[:space:]]*FICHIER_METRIQUES=//p' "$RACINE$SYSCONFIG" | tail -1)
        [ -n "$surcharge" ] && fichier=$surcharge
    fi

    dit "== premiere collecte =="
    systemctl start exporter-freeipa.service || dit "la collecte a rendu une erreur ; le fichier dit laquelle."
    if [ ! -f "$fichier" ]; then
        refus "aucun fichier $fichier : journalctl -u exporter-freeipa.service"
    fi
    series=$(grep -cv '^#' "$fichier" || true)
    reussie=$(awk '$1 == "freeipa_collecte_reussie" {print $2}' "$fichier")
    dit "$series series dans $fichier, freeipa_collecte_reussie=${reussie:-absent}"
    if [ "${reussie:-0}" != 1 ]; then
        dit "une sonde au moins a echoue ; celles qui ont abouti ont tout de meme publie :"
        awk '$1 ~ /^freeipa_collecte_sonde_reussie/ && $2 == 0 {print "  en echec : " $1}' "$fichier"
    fi

    if ! node_exporter_tourne; then
        dit "ATTENTION : node_exporter ne tourne pas ici. Le fichier est ecrit, personne ne le lit."
        exit 2
    fi
    if ! repertoire_servi >/dev/null; then
        dit "ATTENTION : node_exporter tourne sans --collector.textfile.directory. Le fichier est ecrit, personne ne le lit : ajouter --collector.textfile.directory=$textfile a son unite, puis la relancer."
        exit 2
    fi
    dit "en place : node_exporter servira ces series a son prochain scrape."
}

retirer() {
    if [ "$EN_PLACE" = 1 ]; then
        [ "$(id -u)" = 0 ] || refus "a jouer en root."
        systemctl disable --now exporter-freeipa.timer 2>/dev/null || true
    fi
    for f in "$RACINE$UNITES/exporter-freeipa.timer" "$RACINE$UNITES/exporter-freeipa.service" "$RACINE$BIN"; do
        [ -e "$f" ] && { rm -f "$f"; dit "retire : ${f#"$RACINE"}"; }
    done
    [ "$EN_PLACE" = 1 ] && systemctl daemon-reload

    # Un fichier laisse en place serait servi indefiniment : node_exporter ne
    # sait pas qu il est perime, et le tableau montrerait un etat fige.
    local textfile=$TEXTFILE_DEFAUT
    if servi=$(repertoire_servi 2>/dev/null); then textfile=$servi; fi
    for f in "$RACINE$textfile/freeipa.prom" "$RACINE$TEXTFILE_DEFAUT/freeipa.prom"; do
        [ -e "$f" ] && { rm -f "$f"; dit "retire : ${f#"$RACINE"}"; }
    done
    [ -f "$RACINE$SYSCONFIG" ] && dit "$SYSCONFIG laisse en place : il est a vous."
    dit "retire. node_exporter et l annuaire n ont pas ete touches."
}

case "$ACTION" in
    poser) poser ;;
    retirer) retirer ;;
    diagnostic)
        command -v pgrep >/dev/null || refus "pgrep absent (paquet procps-ng) : rien ne peut etre deduit de node_exporter."
        repertoire_servi || refus "aucun node_exporter privilegie ne sert de repertoire textfile." ;;
esac
