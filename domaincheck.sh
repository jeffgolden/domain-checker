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

# Cross-platform date parsing
parse_ssl_date() {
    local date_string="$1"
    case "$PLATFORM" in
        "macOS")
            date -j -f "%b %d %T %Y %Z" "$date_string" "+%s" 2>/dev/null
            ;;
        "Linux"|"FreeBSD")
            date -d "$date_string" "+%s" 2>/dev/null
            ;;
        *)
            echo ""
            ;;
    esac
}

# Banner
print_banner() {
    echo -e "${PURPLE}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}${BOLD}║${NC}                     ${WHITE}DOMAIN INTELLIGENCE${NC}                      ${PURPLE}${BOLD}║${NC}"
    echo -e "${PURPLE}${BOLD}║${NC}                   ${GRAY}Ultimate Domain Checker${NC}                    ${PURPLE}${BOLD}║${NC}"
    echo -e "${PURPLE}${BOLD}║${NC}                        ${GRAY}v${VERSION} • ${PLATFORM}${NC}                        ${PURPLE}${BOLD}║${NC}"
    echo -e "${PURPLE}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
}

# Section headers
print_section() {
    echo -e "\n${CYAN}${BOLD}▓▓▓ $1 ▓▓▓${NC}"
    echo -e "${GRAY}${2}${NC}"
}

# Result formatting
print_result() {
    local status=$1
    local label=$2
    local value=$3
    local color=$4
    
    case "$status" in
        "success")
            echo -e "  ${GREEN}${CHECK}${NC} ${WHITE}${label}:${NC} ${color}${value}${NC}"
            ;;
        "error")
            echo -e "  ${RED}${CROSS}${NC} ${WHITE}${label}:${NC} ${RED}${value}${NC}"
            ;;
        *)
            echo -e "  ${YELLOW}${ARROW}${NC} ${WHITE}${label}:${NC} ${color}${value}${NC}"
            ;;
    esac
}

# DMARC policy parser
parse_dmarc_policy() {
    local dmarc_record=$1
    local clean_record=$(echo "$dmarc_record" | tr -d '"')
    
    local policy=$(echo "$clean_record" | grep -o 'p=[^;]*' | cut -d'=' -f2)
    local subdomain_policy=$(echo "$clean_record" | grep -o 'sp=[^;]*' | cut -d'=' -f2)
    local percentage=$(echo "$clean_record" | grep -o 'pct=[^;]*' | cut -d'=' -f2)
    local alignment_dkim=$(echo "$clean_record" | grep -o 'adkim=[^;]*' | cut -d'=' -f2)
    local alignment_spf=$(echo "$clean_record" | grep -o 'aspf=[^;]*' | cut -d'=' -f2)
    local rua=$(echo "$clean_record" | grep -o 'rua=[^;]*' | cut -d'=' -f2)
    local ruf=$(echo "$clean_record" | grep -o 'ruf=[^;]*' | cut -d'=' -f2)
    
    echo -e "    ${GRAY}Policy Action: ${WHITE}${policy:-none}${NC}"
    [[ -n "$subdomain_policy" ]] && echo -e "    ${GRAY}Subdomain Policy: ${WHITE}${subdomain_policy}${NC}"
    [[ -n "$percentage" ]] && echo -e "    ${GRAY}Enforcement: ${WHITE}${percentage}%${NC}"
    [[ -n "$alignment_dkim" ]] && echo -e "    ${GRAY}DKIM Alignment: ${WHITE}${alignment_dkim}${NC}"
    [[ -n "$alignment_spf" ]] && echo -e "    ${GRAY}SPF Alignment: ${WHITE}${alignment_spf}${NC}"
    [[ -n "$rua" ]] && echo -e "    ${GRAY}Aggregate Reports: ${WHITE}${rua}${NC}"
    [[ -n "$ruf" ]] && echo -e "    ${GRAY}Failure Reports: ${WHITE}${ruf}${NC}"
}

# IP geolocation
get_ip_info() {
    local ip=$1
    local geo_info=$(curl -s --max-time 10 "http://ip-api.com/json/${ip}" 2>/dev/null)
    
    if [[ -n "$geo_info" ]] && echo "$geo_info" | grep -q '"status":"success"'; then
        local country=$(echo "$geo_info" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
        local region=$(echo "$geo_info" | grep -o '"regionName":"[^"]*"' | cut -d'"' -f4)
        local city=$(echo "$geo_info" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
        local isp=$(echo "$geo_info" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
        local org=$(echo "$geo_info" | grep -o '"org":"[^"]*"' | cut -d'"' -f4)
        
        echo "${city}, ${region}, ${country}"
        [[ -n "$isp" ]] && echo "ISP: ${isp}"
        [[ "$org" != "$isp" && -n "$org" ]] && echo "Org: ${org}"
    else
        echo "Geolocation data unavailable"
    fi
}

# Main domain analysis function
analyze_domain() {
    local domain=$1
    
    print_banner
    echo -e "\n${WHITE}${BOLD}Analyzing: ${YELLOW}${domain}${NC}\n"
    
    # DNS Resolution
    print_section "DNS RESOLUTION ${GLOBE}" "Core DNS records and IP information"
    
    local a_record=$(dig +short +time=10 A "$domain" 2>/dev/null | head -1)
    if [[ -n "$a_record" && "$a_record" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_result "success" "IPv4 Address" "$a_record" "${GREEN}"
        
        local geo_data=$(get_ip_info "$a_record")
        if [[ -n "$geo_data" ]]; then
            echo "$geo_data" | while IFS= read -r line; do
                [[ -n "$line" ]] && echo -e "    ${GRAY}${line}${NC}"
            done
        fi
    else
        print_result "error" "IPv4 Address" "Not found" "${RED}"
        a_record=""
    fi
    
    local aaaa_record=$(dig +short +time=10 AAAA "$domain" 2>/dev/null | head -1)
    if [[ -n "$aaaa_record" && "$aaaa_record" =~ : ]]; then
        print_result "success" "IPv6 Address" "$aaaa_record" "${GREEN}"
    else
        print_result "info" "IPv6 Address" "Not configured" "${YELLOW}"
    fi
    
    # DNS Records
    print_section "DNS RECORDS 📋" "Complete DNS record analysis"
    
    # NS Records
    local ns_records=$(dig +short +time=10 NS "$domain" 2>/dev/null)
    if [[ -n "$ns_records" ]]; then
        local ns_count=$(echo "$ns_records" | wc -l | tr -d ' ')
        print_result "success" "Name Servers" "${ns_count} configured" "${GREEN}"
        echo "$ns_records" | while read -r ns; do
            [[ -n "$ns" ]] && echo -e "    ${GRAY}${ARROW} ${ns}${NC}"
        done
    fi
    
    # MX Records
    local mx_records=$(dig +short +time=10 MX "$domain" 2>/dev/null)
    if [[ -n "$mx_records" ]]; then
        local mx_count=$(echo "$mx_records" | wc -l | tr -d ' ')
        print_result "success" "Mail Servers" "${mx_count} configured" "${GREEN}"
        echo "$mx_records" | while read -r mx; do
            [[ -n "$mx" ]] && echo -e "    ${GRAY}${MAIL} ${mx}${NC}"
        done
    else
        print_result "error" "Mail Servers" "No MX records found" "${RED}"
    fi
    
    # Email Security
    print_section "EMAIL SECURITY ${SHIELD}" "SPF, DKIM, and DMARC configuration"
    
    local txt_records=$(dig +short +time=10 TXT "$domain" 2>/dev/null)
    if [[ -n "$txt_records" ]]; then
        local txt_count=$(echo "$txt_records" | wc -l | tr -d ' ')
        print_result "success" "TXT Records" "${txt_count} found" "${GREEN}"
        
        # SPF Check
        local spf_found=false
        echo "$txt_records" | while read -r txt; do
            if [[ "$txt" =~ v=spf1 ]]; then
                echo -e "    ${GREEN}${LOCK} SPF configured: ${WHITE}$(echo "$txt" | tr -d '"')${NC}"
                spf_found=true
            fi
        done
        
        # DKIM Check
        local dkim_selectors=("default" "google" "selector1" "selector2" "k1" "dkim" "fm1")
        local dkim_found=false
        for selector in "${dkim_selectors[@]}"; do
            local dkim_record=$(dig +short +time=5 TXT "${selector}._domainkey.${domain}" 2>/dev/null)
            if [[ -n "$dkim_record" ]]; then
                echo -e "    ${GREEN}${LOCK} DKIM selector '${selector}' configured${NC}"
                dkim_found=true
            fi
        done
        [[ "$dkim_found" == false ]] && echo -e "    ${YELLOW}${ARROW} DKIM: No common selectors found (may still be configured)${NC}"
    fi
    
    # DMARC Check
    local dmarc_record=$(dig +short +time=10 TXT "_dmarc.$domain" 2>/dev/null)
    if [[ -n "$dmarc_record" ]]; then
        print_result "success" "DMARC Policy" "Configured" "${GREEN}"
        parse_dmarc_policy "$dmarc_record"
    else
        print_result "error" "DMARC Policy" "Not configured" "${RED}"
        echo -e "    ${GRAY}Consider implementing DMARC for email authentication${NC}"
    fi
    
    # Web Services
    print_section "WEB SERVICES 🌐" "HTTP/HTTPS connectivity and SSL analysis"
    
    # HTTP Check
    local http_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://$domain" 2>/dev/null)
    if [[ "$http_status" =~ ^[2-3] ]]; then
        print_result "success" "HTTP (Port 80)" "Responding (${http_status})" "${GREEN}"
    elif [[ -n "$http_status" && "$http_status" != "000" ]]; then
        print_result "info" "HTTP (Port 80)" "Status: ${http_status}" "${YELLOW}"
    else
        print_result "error" "HTTP (Port 80)" "Not responding" "${RED}"
    fi
    
    # HTTPS Check
    local https_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$domain" 2>/dev/null)
    if [[ "$https_status" =~ ^[2-3] ]]; then
        print_result "success" "HTTPS (Port 443)" "Responding (${https_status})" "${GREEN}"
        
        # SSL Certificate Analysis
        echo -e "\n  ${PURPLE}${BOLD}SSL Certificate Details:${NC}"
        
        local ssl_output=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null)
        local ssl_info=$(echo "$ssl_output" | openssl x509 -noout -text 2>/dev/null)
        
        if [[ -n "$ssl_info" ]]; then
            local issuer=$(echo "$ssl_info" | grep "Issuer:" | cut -d'=' -f2-)
            local subject=$(echo "$ssl_info" | grep "Subject:" | cut -d'=' -f2-)
            local not_after=$(echo "$ssl_info" | grep "Not After" | cut -d':' -f2-)
            
            [[ -n "$subject" ]] && echo -e "    ${GRAY}Issued to: ${WHITE}${subject}${NC}"
            [[ -n "$issuer" ]] && echo -e "    ${GRAY}Issued by: ${WHITE}${issuer}${NC}"
            [[ -n "$not_after" ]] && echo -e "    ${GRAY}Expires: ${WHITE}${not_after}${NC}"
            
            # Certificate expiry calculation
            if [[ -n "$not_after" ]]; then
                local expiry_epoch=$(parse_ssl_date "$not_after")
                local current_epoch=$(date "+%s")
                if [[ -n "$expiry_epoch" && "$expiry_epoch" =~ ^[0-9]+$ ]]; then
                    local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
                    
                    if [[ $days_left -gt 30 ]]; then
                        echo -e "    ${GREEN}${LOCK} Certificate valid (${days_left} days remaining)${NC}"
                    elif [[ $days_left -gt 0 ]]; then
                        echo -e "    ${YELLOW}⚠️  Certificate expires soon (${days_left} days)${NC}"
                    else
                        echo -e "    ${RED}${CROSS} Certificate expired${NC}"
                    fi
                fi
            fi
        fi
        
    elif [[ -n "$https_status" && "$https_status" != "000" ]]; then
        print_result "info" "HTTPS (Port 443)" "Status: ${https_status}" "${YELLOW}"
    else
        print_result "error" "HTTPS (Port 443)" "Not responding" "${RED}"
    fi
    
# Starting from line 331 (# WHOIS Information)

    # WHOIS Information
    print_section "DOMAIN REGISTRATION 📋" "WHOIS and registration details"
    
    local whois_info=$(whois "$domain" 2>/dev/null)
    if [[ -n "$whois_info" ]]; then
        # Basic registration info
        local registrar=$(echo "$whois_info" | grep -i "registrar:" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        local created=$(echo "$whois_info" | grep -i "creation date\|created\|registration date" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        local updated=$(echo "$whois_info" | grep -i "updated date\|last update" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        local expires=$(echo "$whois_info" | grep -i "expir" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        local status=$(echo "$whois_info" | grep -i "status:" | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//')
        
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
        
        # Display basic info
        [[ -n "$registrar" ]] && print_result "success" "Registrar" "$registrar" "${WHITE}"
        [[ -n "$created" ]] && print_result "success" "Registration Date" "$created" "${WHITE}"
        [[ -n "$updated" ]] && print_result "success" "Last Updated" "$updated" "${WHITE}"
        [[ -n "$expires" ]] && print_result "success" "Expiration Date" "$expires" "${WHITE}"
        [[ -n "$status" ]] && print_result "success" "Status" "$status" "${WHITE}"
        
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
        
        # Check for privacy protection
        if echo "$whois_info" | grep -qi "privacy\|proxy\|protected\|redacted\|data protected"; then
            echo -e "\n  ${YELLOW}⚠️  Note: This domain appears to use WHOIS privacy protection${NC}"
        fi
    else
        print_result "error" "WHOIS Data" "Unable to retrieve" "${RED}"
    fi
    print_section "SECURITY HEADERS 🛡️" "HTTP security header analysis"
    
    local headers=$(curl -s -I --max-time 10 "https://$domain" 2>/dev/null)
    
    if echo "$headers" | grep -qi "strict-transport-security"; then
        print_result "success" "HSTS" "Enabled" "${GREEN}"
    else
        print_result "error" "HSTS" "Not enabled" "${RED}"
    fi
    
    if echo "$headers" | grep -qi "x-frame-options"; then
        print_result "success" "X-Frame-Options" "Set" "${GREEN}"
    else
        print_result "error" "X-Frame-Options" "Not set" "${RED}"
    fi
    
    if echo "$headers" | grep -qi "x-content-type-options"; then
        print_result "success" "X-Content-Type-Options" "Set" "${GREEN}"
    else
        print_result "error" "X-Content-Type-Options" "Not set" "${RED}"
    fi
    
    echo -e "\n${GRAY}${BOLD}Analysis complete for ${WHITE}${domain}${NC}"
    echo -e "${GRAY}Generated on $(date) • Platform: ${PLATFORM}${NC}\n"
}

# Help function
show_help() {
    echo -e "${WHITE}${BOLD}${SCRIPT_NAME} v${VERSION}${NC}"
    echo -e "${GRAY}Cross-platform domain security and DNS analysis tool${NC}\n"
    echo -e "${WHITE}Usage:${NC}"
    echo -e "  $0 <domain>              Analyze a domain"
    echo -e "  $0 --help               Show this help message"
    echo -e "  $0 --version            Show version information"
    echo -e "  $0 --check-deps         Check dependencies"
    echo
    echo -e "${WHITE}Examples:${NC}"
    echo -e "  $0 google.com"
    echo -e "  $0 example.org"
    echo -e "  $0 your-company.com"
    echo
    echo -e "${WHITE}Features:${NC}"
    echo -e "  • DNS resolution and geolocation"
    echo -e "  • Email security analysis (SPF, DKIM, DMARC)"
    echo -e "  • SSL/TLS certificate monitoring"
    echo -e "  • Security headers assessment"
    echo -e "  • WHOIS registration data"
    echo
    echo -e "${WHITE}Supported Platforms:${NC}"
    echo -e "  • macOS (Darwin)"
    echo -e "  • Linux (all distributions)"
    echo -e "  • FreeBSD"
    echo
}

# Version function
show_version() {
    echo -e "${WHITE}${BOLD}${SCRIPT_NAME}${NC}"
    echo -e "Version: ${VERSION}"
    echo -e "Platform: ${PLATFORM}"
    echo -e "Shell: ${BASH_VERSION}"
    echo -e "License: MIT"
}

# Main execution
main() {
    # Detect platform first
    detect_platform
    
    # Handle arguments
    case "${1:-}" in
        "--help"|"-h")
            show_help
            exit 0
            ;;
        "--version"|"-v")
            show_version
            exit 0
            ;;
        "--check-deps")
            echo -e "${WHITE}Checking dependencies...${NC}"
            check_dependencies
            echo -e "${GREEN}All dependencies are installed!${NC}"
            exit 0
            ;;
        "")
            echo -e "${RED}Error: Domain name required${NC}"
            echo -e "Usage: $0 <domain>"
            echo -e "Try '$0 --help' for more information."
            exit 1
            ;;
        -*)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            echo -e "Try '$0 --help' for more information."
            exit 1
            ;;
    esac
    
    # Check dependencies
    check_dependencies
    
    # Clean domain input
    local domain="$1"
    domain=$(echo "$domain" | sed 's|^https\?://||' | sed 's|/.*||' | tr '[:upper:]' '[:lower:]')
    
    # Validate domain format
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo -e "${RED}Error: Invalid domain format '$domain'${NC}"
        exit 1
    fi
    
    # Run analysis
    analyze_domain "$domain"
}

# Execute main function with all arguments
main "$@"
