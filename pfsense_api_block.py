#!/usr/bin/env python3
import sys
import json
import requests
import urllib3

# Desativa alertas de certificado (necessário para SSL autoassinado)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURAÇÕES ---
PFSENSE_IP = "192.168.1.1"  # IP do seu pfSense
API_KEY = "ba4a10e7447802029a7c45aed6c19f5c"  # Sua API Key que funcionou
ALIAS_NAME = "Tpot_Blocklist"  # O nome do Alias que você criou
# ---------------------

def main():
    # 1. Ler o alerta do Wazuh via STDIN
    try:
        input_data = sys.stdin.read()
        alert_json = json.loads(input_data)
    except Exception:
        sys.exit(1)

    # 2. Extrair o IP do atacante (src_ip)
    src_ip = None
    try:
        # Tenta pegar o IP no caminho padrão
        src_ip = alert_json.get("parameters", {}).get("alert", {}).get("data", {}).get("src_ip")
        
        # Se falhar, tenta o caminho alternativo
        if not src_ip:
            src_ip = alert_json.get("parameters", {}).get("alert", {}).get("data", {}).get("src_ip", None)
    except KeyError:
        pass

    if not src_ip:
        sys.exit(1) # Aborta se não achar IP

    # 3. Preparar a requisição para a API do pfSense
    # Usamos o endpoint v1 para adicionar entrada no Alias (padrão do pfrest)
    url = f"https://{PFSENSE_IP}/api/v1/firewall/alias/entry"
    
    # Autenticação via Header X-API-Key
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    
    payload = {
        "name": ALIAS_NAME,
        "address": [src_ip],
        "detail": f"Blocked by Wazuh (Auto) - {src_ip}"
    }
    
    # 4. Enviar o bloqueio
    try:
        response = requests.post(
            url, 
            headers=headers, # Passamos o header com a chave aqui
            json=payload, 
            verify=False # Ignora erro de SSL
        )
        
        # Códigos 200 (OK) ou 201 (Created) indicam sucesso
        if response.status_code in [200, 201]:
            sys.exit(0)
        else:
            # Se falhar, você pode descomentar abaixo para debugar em um arquivo
            # with open("/tmp/wazuh_api_debug.log", "a") as f: 
            #     f.write(f"Erro {response.status_code}: {response.text}\n")
            sys.exit(1)
            
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    main()
