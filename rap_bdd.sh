#!/bin/bash

DATE_DEBUT="2025-08-29 08:00:00"
DATE_FIN="2025-08-29 18:00:00"

RAPPORT="rap_bdd.log"
> $RAPPORT

NOW=$(date +"%Y-%m-%d %H:%M:%S")
if [[ "$NOW" < "$DATE_DEBUT" || "$NOW" > "$DATE_FIN" ]]; then
    echo "[INFO] Hors de la fenêtre temporelle ($DATE_DEBUT → $DATE_FIN)" >> $RAPPORT
    exit 0
fi

echo "===== RAPPORT BASES DE DONNEES ($(date)) =====" >> $RAPPORT

# MySQL / MariaDB
if systemctl list-units --type=service | grep -q "mysql"; then
    echo "--- MySQL détecté ---" >> $RAPPORT
    LOG=$(mysql --help | grep "log-error" | awk '{print $2}' | head -n 1)
    [ -z "$LOG" ] && LOG="/var/log/mysql/error.log"
    tail -n 30 $LOG >> $RAPPORT 2>/dev/null
fi

# PostgreSQL
if systemctl list-units --type=service | grep -q "postgresql"; then
    echo "--- PostgreSQL détecté ---" >> $RAPPORT
    PG_LOG=$(psql -t -c "SHOW log_directory;" 2>/dev/null)
    [ -z "$PG_LOG" ] && PG_LOG="/var/log/postgresql/postgresql-*.log"
    tail -n 30 $PG_LOG >> $RAPPORT 2>/dev/null
fi

# Oracle DB (recherche des alert.log)
if systemctl list-units --type=service | grep -q "oracle"; then
    echo "--- Oracle détecté ---" >> $RAPPORT
    ALERT_LOG=$(find /u01/app/oracle -name "alert*.log" 2>/dev/null | head -n 1)
    [ -n "$ALERT_LOG" ] && tail -n 30 $ALERT_LOG >> $RAPPORT
fi
