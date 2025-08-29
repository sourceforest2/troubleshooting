#!/bin/bash

DATE_DEBUT="2025-08-29 08:00:00"
DATE_FIN="2025-08-29 18:00:00"

RAPPORT="rap_application.log"
> $RAPPORT

NOW=$(date +"%Y-%m-%d %H:%M:%S")
if [[ "$NOW" < "$DATE_DEBUT" || "$NOW" > "$DATE_FIN" ]]; then
    echo "[INFO] Hors de la fenêtre temporelle ($DATE_DEBUT → $DATE_FIN)" >> $RAPPORT
    exit 0
fi

echo "===== RAPPORT APPLICATION ($(date)) =====" >> $RAPPORT

# Apache logs
if systemctl list-units --type=service | grep -q "httpd"; then
    echo "--- Apache détecté ---" >> $RAPPORT
    tail -n 30 /var/log/httpd/error_log >> $RAPPORT 2>/dev/null
elif systemctl list-units --type=service | grep -q "apache2"; then
    echo "--- Apache2 détecté ---" >> $RAPPORT
    tail -n 30 /var/log/apache2/error.log >> $RAPPORT 2>/dev/null
fi

# Nginx logs
if systemctl list-units --type=service | grep -q "nginx"; then
    echo "--- Nginx détecté ---" >> $RAPPORT
    tail -n 30 /var/log/nginx/error.log >> $RAPPORT 2>/dev/null
fi

# Tomcat logs
if systemctl list-units --type=service | grep -q "tomcat"; then
    echo "--- Tomcat détecté ---" >> $RAPPORT
    tail -n 30 /var/log/tomcat*/catalina.out >> $RAPPORT 2>/dev/null
fi
