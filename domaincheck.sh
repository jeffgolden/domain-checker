#!/bin/bash

#==============================================================================
# Domain Intelligence Checker
# Cross-platform domain security and DNS analysis tool
#
# Author: Jeff Golden
# License: MIT
# Repository: https://github.com/jeffgolden/domain-checker
#==============================================================================

# Version information
VERSION="2.1.0"
SCRIPT_NAME="Domain Intelligence Checker"

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Unicode symbols
CHECK="✓"
CROSS="✗"
ARROW="→"
GLOBE="🌍"
LOCK="🔒"
MAIL="📧"
SHIELD="🛡️"

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Darwin*)    PLATFORM="macOS" ;;
        Linux*)     PLATFORM="Linux" ;;
        FreeBSD*)   PLATFORM="FreeBSD" ;;
        CYGWIN*|MINGW*|MSYS*) PLATFORM="Windows" ;;
        *)          PLATFORM="Unknown" ;;
    esac
}

# Check dependencies
check_dependencies() {
    local deps=("dig" "curl" "whois" "openssl")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Missing dependencies: ${missing[*]}${NC}"
        echo
        case "$PLATFORM" in
            "macOS")
                echo -e "${YELLOW}Install with Homebrew:${NC}"
                echo "brew install bind whois curl openssl"
                ;;
            "Linux")
                echo -e "${YELLOW}Install with package manager:${NC}"
                echo "# Ubuntu/Debian:"
                echo "sudo apt install dnsutils whois curl openssl"
                echo "# RHEL/CentOS/Fedora:"
                echo "sudo yum install bind-utils whois curl openssl"
                ;;
            "FreeBSD")
                echo -e "${YELLOW}Install with pkg:${NC}"
                echo "sudo pkg install bind-tools whois curl openssl"
                ;;
        esac
        echo
        exit 1
    fi
}

# Print section header
print_section() {
    local title="$1"
    local description="$2"
    echo
    echo -e "${CYAN}${BOLD}▓▓▓ $title ▓▓▓${NC}"
    [[ -n "$description" ]] && echo -e "${GRAY}$description${NC}"
}

# Print result with formatting
print_result() {
    local status="$1"
    local label="$2"
    local value="$3"
    local color="${4:-$NC}"
    
    case "$status" in
        "success") echo -e "  ${GREEN}${CHECK}${NC} ${WHITE}$label:${NC} ${color}$value${NC}" ;;
        "error")   echo -e "  ${RED}${CROSS}${NC} ${WHITE}$label:${NC} ${color}$value${NC}" ;;
        "info")    echo -e "  ${YELLOW}${ARROW}${NC} ${WHITE}$label:${NC} ${color}$value${NC}" ;;
        *)         echo -e "  ${WHITE}$label:${NC} ${color}$value${NC}" ;;
    esac
}

# Get HTTP status code
get_http_status() {
    local domain="$1"
    curl -sI "https://$domain" -m 5 | head -1 | awk '{print $2}'
}

# Get SSL certificate info
get_ssl_info() {
    local domain="$1"
    echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | \
        openssl x509 -noout -text 2>/dev/null
}

# DNS lookup wrapper
dns_lookup() {
    local record_type="$1"
    local domain="$2"
    local nameserver="${3:-}"
    
    if [[ -n "$nameserver" ]]; then
        dig +short "$record_type" "$domain" "@$nameserver" 2>/dev/null
    else
        dig +short "$record_type" "$domain" 2>/dev/null
    fi
}

# Check SPF record
check_spf() {
    local domain="$1"
    local spf_records=$(dns_lookup TXT "$domain" | grep -E "^\"?v=spf1")
    
    if [[ -n "$spf_records" ]]; then
        echo "$spf_records" | while IFS= read -r spf; do
            # Clean up quotes
            spf=$(echo "$spf" | sed 's/^"//; s/"$//')
            
            # Check for common SPF mechanisms
            local mechanisms=""
            [[ "$spf" =~ "-all" ]] && mechanisms="Fail all (strict)"
            [[ "$spf" =~ "~all" ]] && mechanisms="SoftFail (recommended)"
            [[ "$spf" =~ "\+all" ]] && mechanisms="Pass all (insecure)"
            [[ "$spf" =~ "\?all" ]] && mechanisms="Neutral"
            
            print_result "success" "SPF Record" "Found" "${GREEN}"
            print_result "info" "  Policy" "$spf" "${GRAY}"
            [[ -n "$mechanisms" ]] && print_result "info" "  Enforcement" "$mechanisms" "${CYAN}"
            
            # Check for included domains
            local includes=$(echo "$spf" | grep -o 'include:[^ ]*' | cut -d: -f2)
            if [[ -n "$includes" ]]; then
                echo -e "    ${BOLD}Includes:${NC}"
                echo "$includes" | while read -r inc; do
                    echo -e "      ${GRAY}• $inc${NC}"
                done
            fi
        done
    else
        print_result "error" "SPF Record" "Not found" "${RED}"
        echo -e "    ${YELLOW}⚠ Email spoofing protection not configured${NC}"
    fi
}

# Check DKIM selector
check_dkim_selector() {
    local domain="$1"
    local selector="$2"
    local dkim_record=$(dns_lookup TXT "${selector}._domainkey.${domain}")
    
    if [[ -n "$dkim_record" ]]; then
        print_result "success" "  $selector" "Found" "${GREEN}"
        # Extract key info if present
        if [[ "$dkim_record" =~ "p=" ]]; then
            local key_present="Public key present"
            [[ "$dkim_record" =~ "p=;" ]] && key_present="Key revoked"
            echo -e "      ${GRAY}$key_present${NC}"
        fi
    else
        print_result "info" "  $selector" "Not configured" "${GRAY}"
    fi
}

# Check DMARC record
check_dmarc() {
    local domain="$1"
    local dmarc_record=$(dns_lookup TXT "_dmarc.${domain}")
    
    if [[ -n "$dmarc_record" ]]; then
        # Clean up quotes
        dmarc_record=$(echo "$dmarc_record" | sed 's/^"//; s/"$//')
        
        print_result "success" "DMARC Record" "Found" "${GREEN}"
        print_result "info" "  Policy" "$dmarc_record" "${GRAY}"
        
        # Extract key DMARC tags
        local policy="none"
        [[ "$dmarc_record" =~ "p=reject" ]] && policy="reject (strict)"
        [[ "$dmarc_record" =~ "p=quarantine" ]] && policy="quarantine (moderate)"
        [[ "$dmarc_record" =~ "p=none" ]] && policy="none (monitoring only)"
        
        print_result "info" "  Protection Level" "$policy" "${CYAN}"
        
        # Check for reporting
        if [[ "$dmarc_record" =~ "rua=" ]] || [[ "$dmarc_record" =~ "ruf=" ]]; then
            print_result "info" "  Reporting" "Enabled" "${GREEN}"
        fi
    else
        print_result "error" "DMARC Record" "Not found" "${RED}"
        echo -e "    ${YELLOW}⚠ No email authentication policy${NC}"
    fi
}

# Main analysis function
analyze_domain() {
    local domain="$1"
    
    # Clean domain input
    domain=$(echo "$domain" | sed 's|https\?://||; s|/.*||; s|^www\.||')
    
    echo -e "${BOLD}${WHITE}Analyzing domain: ${CYAN}$domain${NC}"
    echo -e "${GRAY}Generated on $(date) • Platform: $PLATFORM${NC}"
    
    # Basic DNS Records
    print_section "DNS RECORDS 🌐" "Core DNS configuration"
    
    local a_record=$(dns_lookup A "$domain")
    local aaaa_record=$(dns_lookup AAAA "$domain")
    local mx_records=$(dns_lookup MX "$domain")
    local ns_records=$(dns_lookup NS "$domain")
    
    if [[ -n "$a_record" ]]; then
        print_result "success" "A Record" "$a_record" "${WHITE}"
    else
        print_result "error" "A Record" "Not found" "${RED}"
    fi
    
    if [[ -n "$aaaa_record" ]]; then
        print_result "success" "AAAA Record" "$aaaa_record" "${WHITE}"
    else
        print_result "info" "AAAA Record" "No IPv6" "${GRAY}"
    fi
    
    if [[ -n "$mx_records" ]]; then
        print_result "success" "MX Records" "" "${GREEN}"
        echo "$mx_records" | while read -r mx; do
            echo -e "    ${GRAY}• $mx${NC}"
        done
    else
        print_result "error" "MX Records" "Not found" "${RED}"
    fi
    
    if [[ -n "$ns_records" ]]; then
        print_result "success" "Nameservers" "" "${GREEN}"
        echo "$ns_records" | while read -r ns; do
            echo -e "    ${GRAY}• $ns${NC}"
        done
    fi
    
    # WHOIS Information
    print_section "DOMAIN REGISTRATION 📋" "WHOIS and registration details"
    
    local whois_info=$(whois "$domain" 2>/dev/null)
    if [[ -n "$whois_info" ]]; then
        # Basic registration info
        local registrar=$(echo "$whois_info" | grep -i "registrar:" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        local created=$(echo "$whois_info" | grep -i "creation date:\|registration date:" | grep -v "organisation\|remarks" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        local updated=$(echo "$whois_info" | grep -i "updated date\|last update" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        local expires=$(echo "$whois_info" | grep -i "expir" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        local status=$(echo "$whois_info" | grep -i "status:" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        
        # Display basic info
        [[ -n "$registrar" ]] && print_result "success" "Registrar" "$registrar" "${WHITE}"
        [[ -n "$created" ]] && print_result "success" "Registration Date" "$created" "${WHITE}"
        [[ -n "$updated" ]] && print_result "success" "Last Updated" "$updated" "${WHITE}"
        [[ -n "$expires" ]] && print_result "success" "Expiration Date" "$expires" "${WHITE}"
        [[ -n "$status" ]] && print_result "success" "Status" "$status" "${WHITE}"
        
        # Check for privacy protection
        if echo "$whois_info" | grep -qi "privacy\|proxy\|protected\|redacted\|data protected\|withheld\|anonymi"; then
            echo -e "\n  ${YELLOW}🔒 WHOIS Privacy Protection Active${NC}"
            echo -e "  ${GRAY}Contact information is hidden by privacy service${NC}"
        else
            # Only show contact info if NOT privacy protected
            # Registrant information
            local registrant_name=$(echo "$whois_info" | grep -i "registrant name\|registrant:" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            local registrant_org=$(echo "$whois_info" | grep -i "registrant organi" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            local registrant_email=$(echo "$whois_info" | grep -i "registrant email" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            local registrant_country=$(echo "$whois_info" | grep -i "registrant country" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            local registrant_state=$(echo "$whois_info" | grep -i "registrant state\|registrant province" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            
            # Admin contact
            local admin_name=$(echo "$whois_info" | grep -i "admin name" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            local admin_email=$(echo "$whois_info" | grep -i "admin email" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            
            # Tech contact
            local tech_name=$(echo "$whois_info" | grep -i "tech name" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            local tech_email=$(echo "$whois_info" | grep -i "tech email" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
            
            # Display registrant info if available
            if [[ -n "$registrant_name" ]] || [[ -n "$registrant_org" ]] || [[ -n "$registrant_email" ]]; then
                echo -e "\n  ${BOLD}Registrant Information:${NC}"
                [[ -n "$registrant_name" ]] && print_result "info" "  Name" "$registrant_name" "${CYAN}"
                [[ -n "$registrant_org" ]] && print_result "info" "  Organization" "$registrant_org" "${CYAN}"
                [[ -n "$registrant_email" ]] && print_result "info" "  Email" "$registrant_email" "${CYAN}"
                [[ -n "$registrant_country" ]] && print_result "info" "  Country" "$registrant_country" "${CYAN}"
                [[ -n "$registrant_state" ]] && print_result "info" "  State/Province" "$registrant_state" "${CYAN}"
            fi
            
            # Display admin contact if available
            if [[ -n "$admin_name" ]] || [[ -n "$admin_email" ]]; then
                echo -e "\n  ${BOLD}Administrative Contact:${NC}"
                [[ -n "$admin_name" ]] && print_result "info" "  Name" "$admin_name" "${CYAN}"
                [[ -n "$admin_email" ]] && print_result "info" "  Email" "$admin_email" "${CYAN}"
            fi
            
            # Display tech contact if available
            if [[ -n "$tech_name" ]] || [[ -n "$tech_email" ]]; then
                echo -e "\n  ${BOLD}Technical Contact:${NC}"
                [[ -n "$tech_name" ]] && print_result "info" "  Name" "$tech_name" "${CYAN}"
                [[ -n "$tech_email" ]] && print_result "info" "  Email" "$tech_email" "${CYAN}"
            fi
        fi
    else
        print_result "error" "WHOIS Data" "Unable to retrieve" "${RED}"
    fi
    
    # Security Headers
    print_section "SECURITY HEADERS 🛡️" "HTTP security header analysis"
    
    local headers=$(curl -sI "https://$domain" -m 5)
    if [[ -n "$headers" ]]; then
        # Check for common security headers
        local hsts=$(echo "$headers" | grep -i "strict-transport-security")
        local frame_options=$(echo "$headers" | grep -i "x-frame-options")
        local content_type=$(echo "$headers" | grep -i "x-content-type-options")
        
        if [[ -n "$hsts" ]]; then
            print_result "success" "HSTS" "Enabled" "${GREEN}"
        else
            print_result "error" "HSTS" "Not enabled" "${RED}"
        fi
        
        if [[ -n "$frame_options" ]]; then
            print_result "success" "X-Frame-Options" "Set" "${GREEN}"
        else
            print_result "error" "X-Frame-Options" "Not set" "${RED}"
        fi
        
        if [[ -n "$content_type" ]]; then
            print_result "success" "X-Content-Type-Options" "Set" "${GREEN}"
        else
            print_result "error" "X-Content-Type-Options" "Not set" "${RED}"
        fi
    else
        print_result "error" "Security Headers" "Could not retrieve" "${RED}"
    fi
    
    # SSL Certificate
    print_section "SSL CERTIFICATE 🔒" "TLS/SSL certificate details"
    
    local ssl_info=$(get_ssl_info "$domain")
    if [[ -n "$ssl_info" ]]; then
        local issuer=$(echo "$ssl_info" | grep -A1 "Issuer:" | tail -1 | sed 's/^[[:space:]]*//')
        local subject=$(echo "$ssl_info" | grep -A1 "Subject:" | tail -1 | sed 's/^[[:space:]]*//')
        local not_after=$(echo "$ssl_info" | grep "Not After" | cut -d: -f2- | sed 's/^[[:space:]]*//')
        
        print_result "success" "SSL Certificate" "Valid" "${GREEN}"
        [[ -n "$issuer" ]] && print_result "info" "Issuer" "$issuer" "${WHITE}"
        [[ -n "$not_after" ]] && print_result "info" "Expires" "$not_after" "${WHITE}"
        
        # Check expiration
        if [[ -n "$not_after" ]]; then
            local exp_date=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$not_after" +%s 2>/dev/null)
            local now=$(date +%s)
            local days_left=$(( (exp_date - now) / 86400 ))
            
            if [[ $days_left -lt 30 ]]; then
                print_result "error" "Days until expiry" "$days_left days" "${RED}"
                echo -e "    ${RED}⚠ Certificate expiring soon!${NC}"
            else
                print_result "info" "Days until expiry" "$days_left days" "${GREEN}"
            fi
        fi
    else
        print_result "error" "SSL Certificate" "Could not retrieve" "${RED}"
    fi
    
    # Email Security
    print_section "EMAIL SECURITY 📧" "SPF, DKIM, and DMARC configuration"
    
    # SPF Check
    check_spf "$domain"
    
    # DKIM Check
    echo
    print_result "info" "DKIM Selectors" "Checking common selectors..." "${CYAN}"
    local selectors=("default" "google" "k1" "s1" "s2" "mail" "smtp" "dkim" "email" "key1" "key2")
    local dkim_found=false
    
    for selector in "${selectors[@]}"; do
        local dkim_record=$(dns_lookup TXT "${selector}._domainkey.${domain}" | grep -v "^;;")
        if [[ -n "$dkim_record" ]]; then
            dkim_found=true
            check_dkim_selector "$domain" "$selector"
        fi
    done
    
    if [[ "$dkim_found" == false ]]; then
        print_result "error" "DKIM" "No selectors found" "${RED}"
        echo -e "    ${YELLOW}⚠ Email authentication not configured${NC}"
    fi
    
    # DMARC Check
    echo
    check_dmarc "$domain"
    
    # Website Status
    print_section "WEBSITE STATUS 🌍" "HTTP/HTTPS connectivity check"
    
    local http_status=$(get_http_status "$domain")
    if [[ -n "$http_status" ]]; then
        case "$http_status" in
            200) print_result "success" "HTTPS Status" "$http_status OK" "${GREEN}" ;;
            301|302) print_result "info" "HTTPS Status" "$http_status Redirect" "${YELLOW}" ;;
            403) print_result "error" "HTTPS Status" "$http_status Forbidden" "${RED}" ;;
            404) print_result "error" "HTTPS Status" "$http_status Not Found" "${RED}" ;;
            5*) print_result "error" "HTTPS Status" "$http_status Server Error" "${RED}" ;;
            *) print_result "info" "HTTPS Status" "$http_status" "${YELLOW}" ;;
        esac
    else
        print_result "error" "HTTPS Status" "Connection failed" "${RED}"
    fi
    
    # Footer
    echo
    echo -e "${GRAY}${BOLD}Analysis complete for ${WHITE}$domain${NC}"
    echo -e "${GRAY}Generated on $(date) • Platform: $PLATFORM${NC}"
    echo
}

# Show help
show_help() {
    cat << EOF
${BOLD}${SCRIPT_NAME} v${VERSION}${NC}
${GRAY}Advanced domain security and DNS analysis tool${NC}

${BOLD}USAGE:${NC}
    $(basename "$0") <domain>
    $(basename "$0") [options]

${BOLD}OPTIONS:${NC}
    -h, --help      Show this help message
    -v, --version   Show version information

${BOLD}EXAMPLES:${NC}
    $(basename "$0") example.com
    $(basename "$0") subdomain.example.com

${BOLD}FEATURES:${NC}
    • DNS record analysis (A, AAAA, MX, NS)
    • WHOIS information with registrant details
    • SSL/TLS certificate validation
    • Security header assessment
    • Email security (SPF, DKIM, DMARC)
    • Website connectivity testing

${BOLD}SUPPORTED PLATFORMS:${NC}
    • macOS
    • Linux (Ubuntu, Debian, RHEL, CentOS, Fedora)
    • FreeBSD

EOF
}

# Main execution
main() {
    detect_platform
    
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            echo "$SCRIPT_NAME v$VERSION"
            exit 0
            ;;
        "")
            show_help
            exit 1
            ;;
        *)
            check_dependencies
            analyze_domain "$1"
            ;;
    esac
}

# Run main function
main "$@"
