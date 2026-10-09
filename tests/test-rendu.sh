#!/bin/sh
# Verifie que le rendu des modeles ne peut pas produire un manifeste a moitie
# substitue : applique, il superviserait silencieusement la mauvaise machine.
set -eu

ici="$(cd "$(dirname "$0")" && pwd)"
racine="$(cd "$ici/.." && pwd)"
atelier="$(mktemp -d)"
trap 'rm -rf "$atelier"' EXIT INT TERM
reussis=0
echoues=0

# Chaque cas joue rendre.sh avec sa propre configuration, jamais celle du poste.
rendre() {
    CONFIGURATION="$atelier/configuration.env" "$racine/rendre.sh" "$@"
}

enonce() { printf '  %-72s ' "$1"; }
reussi() { echo ok; reussis=$((reussis + 1)); }
echoue() { echo "ECHEC : $1"; echoues=$((echoues + 1)); }

complete() { cp "$racine/configuration.env.exemple" "$atelier/configuration.env"; }

enonce "une configuration complete rend les quatre objets attendus"
complete
if rendre "$racine/kubernetes/supervision.yaml.modele" > "$atelier/rendu.yaml" 2>"$atelier/err" \
   && [ "$(python3 -c "import yaml; print([d['kind'] for d in yaml.safe_load_all(open('$atelier/rendu.yaml'))])")" \
        = "['Service', 'Endpoints', 'ServiceMonitor', 'PrometheusRule']" ]; then
    reussi
else
    echoue "$(cat "$atelier/err")"
fi

enonce "aucun marqueur ne subsiste dans le manifeste rendu"
if grep -q '@[A-Z_]*@' "$atelier/rendu.yaml"; then
    echoue "il reste $(grep -o '@[A-Z_]*@' "$atelier/rendu.yaml" | sort -u | tr '\n' ' ')"
else
    reussi
fi

enonce "l adresse configuree est celle que Prometheus ira interroger"
complete
sed -i.bak 's/^ADRESSE_FREEIPA=.*/ADRESSE_FREEIPA=198.51.100.7/' "$atelier/configuration.env"
if rendre "$racine/kubernetes/supervision.yaml.modele" | grep -q 'ip: "198.51.100.7"'; then
    reussi
else
    echoue "l adresse n a pas suivi la configuration"
fi

enonce "le nom de job configure est celui auquel l alerte se refere"
complete
sed -i.bak 's/^NOM_JOB=.*/NOM_JOB=annuaire-maison/' "$atelier/configuration.env"
if rendre "$racine/kubernetes/supervision.yaml.modele" | grep -q 'up{job="annuaire-maison"} == 0'; then
    reussi
else
    echoue "l alerte vise encore un autre job"
fi

enonce "une valeur vide fait echouer le rendu plutot que de laisser un trou"
complete
sed -i.bak 's/^ADRESSE_FREEIPA=.*/ADRESSE_FREEIPA=/' "$atelier/configuration.env"
if rendre "$racine/kubernetes/supervision.yaml.modele" >"$atelier/out" 2>"$atelier/err"; then
    echoue "le rendu a reussi avec une adresse vide"
elif grep -q ADRESSE_FREEIPA "$atelier/err"; then
    reussi
else
    echoue "le message ne nomme pas la valeur manquante : $(cat "$atelier/err")"
fi

enonce "un marqueur inconnu du fichier de configuration est signale"
complete
printf 'ip: "@MARQUEUR_IMPREVU@"\n' > "$atelier/modele-douteux.yaml"
if rendre "$atelier/modele-douteux.yaml" >"$atelier/out" 2>"$atelier/err"; then
    echoue "le rendu a laisse passer un marqueur inconnu"
elif grep -q MARQUEUR_IMPREVU "$atelier/err"; then
    reussi
else
    echoue "$(cat "$atelier/err")"
fi

enonce "une configuration absente est signalee avant toute substitution"
rm -f "$atelier/configuration.env"
if rendre "$racine/kubernetes/supervision.yaml.modele" >"$atelier/out" 2>"$atelier/err"; then
    echoue "le rendu a reussi sans configuration"
elif grep -q "configuration absente" "$atelier/err"; then
    reussi
else
    echoue "$(cat "$atelier/err")"
fi

echo
echo "$reussis reussi(s), $echoues echec(s)."
[ "$echoues" -eq 0 ]
