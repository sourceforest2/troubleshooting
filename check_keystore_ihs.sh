#!/bin/bash

#===============================================================================
# Script d'analyse complète des certificats SSL - Support IHS & Keystores Java
# Auteur: Assistant
# Date: 2025
# Supporte: PEM, JKS, PKCS12, CMS (KDB), et configurations IHS/WebSphere
#===============================================================================

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Variables globales
REPORT_FILE="/tmp/ssl_audit_$(date +%Y%m%d_%H%M%S).txt"
FOUND_CERTS=0
FOUND_KEYS=0
FOUND_KEYSTORES=0
IHS_DETECTED=false

# Mots de passe courants pour keystores (à personnaliser)
COMMON_PASSWORDS=("changeit" "password" "websphere" "ibm-team" "admin" "")

#===============================================================================
# FONCTIONS D'AFFICHAGE
#===============================================================================

print_header() {
    echo -e "\n${BLUE}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "\n=== $1 ===\n" >> "$REPORT_FILE"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[✓] $1" >> "$REPORT_FILE"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[!] $1" >> "$REPORT_FILE"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[✗] $1" >> "$REPORT_FILE"
}

print_info() {
    echo -e "${CYAN}[i]${NC} $1"
    echo "[i] $1" >> "$REPORT_FILE"
}

print_ihs() {
    echo -e "${MAGENTA}[IHS]${NC} $1"
    echo "[IHS] $1" >> "$REPORT_FILE"
}

#===============================================================================
# DÉTECTION IHS ET KEYSTORES
#===============================================================================

detect_ihs_installation() {
    print_header "DÉTECTION IBM HTTP SERVER (IHS)"
    
    local ihs_locations=(
        "/opt/IBM/HTTPServer"
        "/opt/IBM/HttpServer"
        "/usr/IBM/HTTPServer"
        "/opt/IBM/WebSphere/Plugins"
        "/usr/IBM/WebSphere/Plugins"
        "/opt/IBM/HTTPServer9"
        "/opt/IBM/HTTPServer8"
        "C:/Program Files/IBM/HTTPServer"
        "C:/Program Files (x86)/IBM/HTTPServer"
    )
    
    for loc in "${ihs_locations[@]}"; do
        if [ -d "$loc" ]; then
            print_ihs "Installation IHS détectée: $loc"
            IHS_DETECTED=true
            
            # Recherche des fichiers de configuration
            if [ -f "$loc/conf/httpd.conf" ]; then
                print_success "Configuration httpd.conf trouvée"
                analyze_ihs_config "$loc/conf/httpd.conf"
            fi
            
            # Recherche des keystores CMS/KDB
            find_ihs_keystores "$loc"
        fi
    done
    
    if [ "$IHS_DETECTED" = false ]; then
        print_info "Aucune installation IHS détectée dans les emplacements standards"
    fi
}

analyze_ihs_config() {
    local config_file="$1"
    print_info "Analyse de: $config_file"
    
    # Extraction des chemins de keystores
    local keyfiles=$(grep -i "Keyfile\|SSLServerCert\|Keyring" "$config_file" 2>/dev/null | grep -v "^#" || true)
    
    if [ -n "$keyfiles" ]; then
        print_ihs "Configurations SSL trouvées:"
        echo "$keyfiles" | while read -r line; do
            echo "    $line"
            # Extraire le chemin du fichier
            local path=$(echo "$line" | grep -o '".*"' | tr -d '"' || echo "$line" | awk '{print $2}')
            if [ -f "$path" ]; then
                analyze_cms_keystore "$path"
            fi
        done
    fi
}

find_ihs_keystores() {
    local base_dir="$1"
    print_info "Recherche de keystores CMS (.kdb) et PKCS12 (.p12) dans $base_dir"
    
    find "$base_dir" -type f \( -name "*.kdb" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks" \) 2>/dev/null | while read -r keystore; do
        if [[ "$keystore" == *.kdb ]]; then
            analyze_cms_keystore "$keystore"
        else
            analyze_java_keystore "$keystore"
        fi
    done
}

#===============================================================================
# ANALYSE KEYSTORES JAVA (JKS, PKCS12)
#===============================================================================

analyze_java_keystore() {
    local keystore="$1"
    ((FOUND_KEYSTORES++)) || true
    
    print_header "KEYSTORE JAVA DÉTECTÉ: $keystore"
    
    # Détection du type
    local storetype="jks"
    [[ "$keystore" == *.p12 ]] || [[ "$keystore" == *.pfx ]] && storetype="pkcs12"
    
    print_info "Type détecté: $storetype"
    print_info "Permissions: $(stat -c "%a %U:%G" "$keystore" 2>/dev/null || stat -f "%Lp %Su:%Sg" "$keystore")"
    
    # Tentative d'ouverture avec différents mots de passe
    local password=""
    local success=false
    
    for pwd in "${COMMON_PASSWORDS[@]}"; do
        if keytool -list -keystore "$keystore" -storetype "$storetype" -storepass "$pwd" >/dev/null 2>&1; then
            password="$pwd"
            success=true
            if [ -n "$pwd" ]; then
                print_success "Keystore accessible (mot de passe trouvé)"
            else
                print_success "Keystore accessible sans mot de passe"
            fi
            break
        fi
    done
    
    if [ "$success" = false ]; then
        print_warning "Mot de passe requis - entrez-le manuellement ou modifiez COMMON_PASSWORDS"
        echo -e "${YELLOW}Commande pour inspecter manuellement:${NC}"
        echo "keytool -list -v -keystore $keystore -storetype $storetype"
        return
    fi
    
    # Liste des entrées
    echo -e "\n${CYAN}--- Contenu du Keystore ---${NC}"
    keytool -list -keystore "$keystore" -storetype "$storetype" -storepass "$password" 2>/dev/null | grep -E "Entry|Alias|Creation" | while read -r line; do
        echo "  $line"
    done
    
    # Analyse détaillée de chaque entrée
    local aliases=$(keytool -list -keystore "$keystore" -storetype "$storetype" -storepass "$password" 2>/dev/null | grep "Alias name:" | awk '{print $3}')
    
    for alias in $aliases; do
        analyze_keystore_entry "$keystore" "$storetype" "$password" "$alias"
    done
}

analyze_keystore_entry() {
    local keystore="$1"
    local storetype="$2"
    local password="$3"
    local alias="$4"
    
    echo -e "\n${CYAN}--- Analyse de l'entrée: $alias ---${NC}"
    
    # Export des détails
    local details=$(keytool -list -v -keystore "$keystore" -storetype "$storetype" -storepass "$password" -alias "$alias" 2>/dev/null)
    
    # Type d'entrée
    local entry_type=$(echo "$details" | grep "Entry type:" | awk '{print $3}')
    echo -e "Type: ${GREEN}$entry_type${NC}"
    
    if [ "$entry_type" = "PrivateKeyEntry" ]; then
        print_success "Contient une clé privée"
        local chain_length=$(echo "$details" | grep "Certificate chain length:" | awk '{print $4}')
        echo -e "Longueur chaîne: $chain_length"
    elif [ "$entry_type" = "trustedCertEntry" ]; then
        print_info "Certificat de confiance (CA)"
    fi
    
    # Informations du certificat
    local owner=$(echo "$details" | grep "Owner:" | sed 's/Owner: //')
    local issuer=$(echo "$details" | grep "Issuer:" | sed 's/Issuer: //')
    local serial=$(echo "$details" | grep "Serial number:" | awk '{print $3}')
    local valid_from=$(echo "$details" | grep "Valid from:" | sed 's/Valid from: //')
    local valid_until=$(echo "$details" | grep "until:" | sed 's/.*until: //')
    local sig_algo=$(echo "$details" | grep "Signature algorithm name:" | awk '{print $4}')
    local key_algo=$(echo "$details" | grep "Subject Public Key Algorithm:" | awk '{print $5}')
    local key_size=$(echo "$details" | grep -o "[0-9]*-bit" | head -1)
    
    echo -e "Propriétaire: ${GREEN}$owner${NC}"
    echo -e "Émetteur: $issuer"
    echo -e "Série: $serial"
    echo -e "Valide du: $valid_from"
    
    # Vérification de la validité
    local end_date=$(echo "$valid_until" | xargs -I {} date -d "{}" +%s 2>/dev/null || echo "0")
    local now=$(date +%s)
    local days_left=$(( (end_date - now) / 86400 ))
    
    if [ $days_left -lt 0 ]; then
        echo -e "Valide jusqu'au: ${RED}$valid_until (EXPIRÉ)${NC}"
        print_error "Certificat EXPIRÉ dans le keystore!"
    elif [ $days_left -lt 30 ]; then
        echo -e "Valide jusqu'au: ${YELLOW}$valid_until ($days_left jours)${NC}"
        print_warning "Expiration proche!"
    else
        echo -e "Valide jusqu'au: ${GREEN}$valid_until ($days_left jours)${NC}"
    fi
    
    echo -e "Algorithme signature: $sig_algo"
    echo -e "Algorithme clé: $key_algo $key_size"
    
    # Vérification SAN
    local san=$(echo "$details" | grep -A5 "SubjectAlternativeName" | grep "DNSName:" | head -3)
    if [ -n "$san" ]; then
        echo -e "SANs: $san"
    fi
    
    # Empreintes
    local sha256=$(echo "$details" | grep "SHA256:" | awk '{print $2}')
    [ -n "$sha256" ] && echo -e "Empreinte SHA256: $sha256"
}

#===============================================================================
# ANALYSE KEYSTORES CMS (IHS/GSKit)
#===============================================================================

analyze_cms_keystore() {
    local keystore="$1"
    ((FOUND_KEYSTORES++)) || true
    
    print_header "KEYSTORE CMS (IHS) DÉTECTÉ: $keystore"
    
    # Vérification des fichiers associés (.sth pour le stash, .rdb pour les certificats)
    local base_name="${keystore%.kdb}"
    local stash_file="${base_name}.sth"
    local rdb_file="${base_name}.rdb"
    
    print_info "Fichier stash: $([ -f "$stash_file" ] && echo "Présent" || echo "Absent")"
    print_info "Fichier RDB: $([ -f "$rdb_file" ] && echo "Présent" || echo "Absent")"
    
    # Vérification de gskcmd ou gskcapicmd
    local gsk_cmd=""
    if command -v gskcmd &>/dev/null; then
        gsk_cmd="gskcmd"
    elif command -v gskcapicmd &>/dev/null; then
        gsk_cmd="gskcapicmd"
    elif [ -f "/usr/local/ibm/gsk8/bin/gskcmd" ]; then
        gsk_cmd="/usr/local/ibm/gsk8/bin/gskcmd"
    elif [ -f "/opt/IBM/HTTPServer/gsk8/bin/gskcmd" ]; then
        gsk_cmd="/opt/IBM/HTTPServer/gsk8/bin/gskcmd"
    fi
    
    if [ -z "$gsk_cmd" ]; then
        print_warning "GSKit (gskcmd/gskcapicmd) non trouvé - analyse limitée"
        print_info "Installez GSKit ou utilisez iKeyman pour analyser ce keystore"
        return
    fi
    
    print_success "GSKit trouvé: $gsk_cmd"
    
    # Tentative avec stash file
    local gsk_output=""
    if [ -f "$stash_file" ]; then
        gsk_output=$($gsk_cmd -cert -list -db "$keystore" -stashed 2>/dev/null) || true
    fi
    
    # Si échec, essayer sans mot de passe (peut fonctionner pour certains keystores)
    if [ -z "$gsk_output" ]; then
        for pwd in "${COMMON_PASSWORDS[@]}"; do
            gsk_output=$($gsk_cmd -cert -list -db "$keystore" -pw "$pwd" 2>/dev/null) && break
        done
    fi
    
    if [ -n "$gsk_output" ]; then
        print_success "Keystore CMS accessible"
        echo -e "\n${CYAN}--- Certificats dans le keystore ---${NC}"
        echo "$gsk_output" | while read -r line; do
            echo "  • $line"
            # Si c'est un label de certificat, obtenir les détails
            if [[ "$line" == *" "* ]] && [[ "$line" != "Database"* ]]; then
                local label=$(echo "$line" | awk '{print $1}')
                [ -n "$label" ] && analyze_cms_certificate "$keystore" "$label" "$gsk_cmd"
            fi
        done
    else
        print_error "Impossible d'accéder au keystore CMS - mot de passe requis"
    fi
}

analyze_cms_certificate() {
    local keystore="$1"
    local label="$2"
    local gsk_cmd="$3"
    
    local details=""
    if [ -f "${keystore%.kdb}.sth" ]; then
        details=$($gsk_cmd -cert -details -db "$keystore" -label "$label" -stashed 2>/dev/null) || true
    else
        for pwd in "${COMMON_PASSWORDS[@]}"; do
            details=$($gsk_cmd -cert -details -db "$keystore" -label "$label" -pw "$pwd" 2>/dev/null) && break
        done
    fi
    
    if [ -n "$details" ]; then
        echo -e "\n  ${YELLOW}Détails pour '$label':${NC}"
        echo "$details" | grep -E "Key Size|Version|Serial|Issued by|Subject|Valid|Fingerprint|Algorithm" | while read -r line; do
            echo "    $line"
        done
    fi
}

#===============================================================================
# RECHERCHE GÉNÉRALE DE KEYSTORES
#===============================================================================

search_all_keystores() {
    print_header "RECHERCHE DE TOUS LES KEYSTORES"
    
    local search_paths=(
        "/etc/ssl"
        "/etc/pki"
        "/opt/IBM"
        "/usr/IBM"
        "/opt/WebSphere"
        "/usr/WebSphere"
        "/opt/ibm"
        "/var/ibm"
        "/home"
        "/root"
        "/opt"
        "/usr/share"
        "/var/lib"
    )
    
    # Recherche par extension
    for path in "${search_paths[@]}"; do
        if [ -d "$path" ]; then
            find "$path" -type f \( -name "*.jks" -o -name "*.p12" -o -name "*.pfx" -o -name "*.kdb" \) 2>/dev/null | while read -r keystore; do
                if [[ "$keystore" == *.kdb ]]; then
                    analyze_cms_keystore "$keystore"
                else
                    analyze_java_keystore "$keystore"
                fi
            done
        fi
    done
    
    # Recherche dans les variables d'environnement Java
    if [ -n "$JAVA_HOME" ]; then
        print_info "Analyse du keystore cacerts Java ($JAVA_HOME)"
        local cacerts="$JAVA_HOME/lib/security/cacerts"
        [ -f "$cacerts" ] && analyze_java_keystore "$cacerts"
    fi
}

#===============================================================================
# FONCTIONS ORIGINALES (PEM/CERTIFICATS STANDARDS)
#===============================================================================

search_standard_certs() {
    print_header "RECHERCHE DES CERTIFICATS STANDARDS (PEM)"
    
    local locations=(
        "/etc/ssl"
        "/etc/pki"
        "/etc/nginx"
        "/etc/apache2"
        "/etc/httpd"
        "/etc/letsencrypt"
    )
    
    for loc in "${locations[@]}"; do
        if [ -d "$loc" ]; then
            find "$loc" -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cert" \) 2>/dev/null | while read -r cert; do
                if openssl x509 -in "$cert" -noout 2>/dev/null; then
                    analyze_standard_cert "$cert"
                fi
            done
        fi
    done
}

analyze_standard_cert() {
    local cert="$1"
    ((FOUND_CERTS++)) || true
    
    print_header "CERTIFICAT PEM: $cert"
    
    local subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/subject=//')
    local issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    local end_date=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
    
    echo -e "Sujet: ${GREEN}$subject${NC}"
    echo -e "Émetteur: $issuer"
    echo -e "Expiration: $end_date"
}

#===============================================================================
# RAPPORT FINAL
#===============================================================================

generate_summary() {
    print_header "RÉSUMÉ DE L'ANALYSE"
    
    print_info "Certificats PEM trouvés: $FOUND_CERTS"
    print_info "Keystores analysés: $FOUND_KEYSTORES"
    print_info "Installation IHS détectée: $([ "$IHS_DETECTED" = true ] && echo "OUI" || echo "NON")"
    print_info "Rapport sauvegardé dans: $REPORT_FILE"
    
    if [ "$IHS_DETECTED" = true ]; then
        echo -e "\n${MAGENTA}Notes spécifiques IHS:${NC}"
        echo "  • Les keystores CMS (.kdb) nécessitent GSKit (gskcmd/gskcapicmd)"
        echo "  • Utilisez iKeyman pour la gestion graphique des keystores"
        echo "  • Vérifiez les fichiers .sth (stash) pour les mots de passe"
    fi
    
    echo -e "\n${CYAN}Commandes utiles pour IHS:${NC}"
    echo "  # Lister les certificats dans un keystore CMS:"
    echo "  gskcmd -cert -list -db /chemin/vers/keystore.kdb -stashed"
    echo ""
    echo "  # Détails d'un certificat spécifique:"
    echo "  gskcmd -cert -details -db keystore.kdb -label 'certname' -stashed"
    echo ""
    echo "  # Exporter un certificat:"
    echo "  gskcmd -cert -extract -db keystore.kdb -label 'certname' -file cert.arm -stashed"
}

#===============================================================================
# EXÉCUTION PRINCIPALE
#===============================================================================

main() {
    echo -e "${BLUE}"
    cat << "EOF"
    ____  _____ _     ____   ____ _   _ _____ ____ _  _______ ____  
   / ___|| ____| |   |  _ \ / ___| | | | ____/ ___| |/ / ____|  _ \ 
   \___ \|  _| | |   | |_) | |   | |_| |  _|| |   | ' /|  _| | |_) |
    ___) | |___| |___|  __/| |___|  _  | |__| |___| . \| |___|  _ < 
   |____/|_____|_____|_|    \____|_| |_|_____\____|_|\_\_____|_| \_\
                                                                    
         SSL AUDIT TOOL - Support IHS / WebSphere / Java Keystores
EOF
    echo -e "${NC}"
    
    # Vérifications de base
    if ! command -v openssl &>/dev/null; then
        print_error "OpenSSL requis mais non installé"
        exit 1
    fi
    
    if ! command -v keytool &>/dev/null; then
        print_warning "Java keytool non trouvé - l'analyse des keystores Java sera limitée"
    fi
    
    echo "Rapport généré le $(date)" > "$REPORT_FILE"
    echo "=======================================" >> "$REPORT_FILE"
    
    # Ordre d'analyse
    detect_ihs_installation      # IHS en priorité
    search_all_keystores         # Tous les keystores Java/CMS
    search_standard_certs        # Certificats standards PEM
    
    generate_summary
}

# Gestion des arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h       Affiche cette aide"
        echo "  --ihs-only       Analyse uniquement la configuration IHS"
        echo "  --java-only      Analyse uniquement les keystores Java"
        echo ""
        echo "Ce script détecte et analyse:"
        echo "  • IBM HTTP Server (IHS) et keystores CMS (.kdb)"
        echo "  • Keystores Java (JKS, PKCS12, PFX)"
        echo "  • Certificats standards (PEM, CRT)"
        echo ""
        echo "Les mots de passe courants peuvent être configurés dans COMMON_PASSWORDS"
        exit 0
        ;;
    --ihs-only)
        detect_ihs_installation
        generate_summary
        ;;
    --java-only)
        search_all_keystores
        generate_summary
        ;;
    *)
        main
        ;;
esac
