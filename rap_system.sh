#!/bin/bash

# Configurer la période d'analyse
DATE_DEBUT="2025-08-29 08:00:00"
DATE_FIN="2025-08-29 18:00:00"

RAPPORT="rap_system.log"
> $RAPPORT

# Vérifie si l'heure courante est dans la plage
NOW=$(date +"%Y-%m-%d %H:%M:%S")
if [[ "$NOW" < "$DATE_DEBUT" || "$NOW" > "$DATE_FIN" ]]; then
    echo "[INFO] Hors de la fenêtre temporelle ($DATE_DEBUT → $DATE_FIN)" >> $RAPPORT
    exit 0
fi

echo "===== RAPPORT SYSTEME ($(date)) =====" >> $RAPPORT

# Exemple : messages système (RedHat, Debian)
if [ -f /var/log/messages ]; then
    echo "--- Dernières erreurs système ---" >> $RAPPORT
    grep -i "error" /var/log/messages | tail -n 20 >> $RAPPORT
elif [ -f /var/log/syslog ]; then
    echo "--- Dernières erreurs système ---" >> $RAPPORT
    grep -i "error" /var/log/syslog | tail -n 20 >> $RAPPORT
fi

# Espace disque
echo "--- Etat disque ---" >> $RAPPORT
df -h >> $RAPPORT

# Charge CPU / RAM
echo "--- Charge système ---" >> $RAPPORT
uptime >> $RAPPORT
free -h >> $RAPPORT
