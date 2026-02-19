#!/usr/bin/env python3
import sys
import json
import requests
import urllib3

# Desativa alertas de certificado
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURAÇÕES ---
PFSENSE_IP = "192.168.1.1"
API_KEY = "94a811d4db9ce451316af21f80ac8cb3" # Sua Key
ALIAS_NAME = "Tpot_Blocklist"
# ---------------------

def log_debug(msg):
    try:
        with open("/var/ossec/logs/active-responses.log", "a") as f:
            f.write(f"pfSense-Block: {msg}\n")
    except:
        pass
    if sys.stdout.isatty():
        print(msg)

def main():
    log_debug("Script iniciado. Aguardando JSON...")
    # 1. Leitura do JSON
    try:
        input_data = sys.stdin.readline()
        
        if not input_data:
            log_debug("Erro: Nenhum dado recebido via STDIN")
            sys.exit(1)
            
        alert_json = json.loads(input_data)
    except Exception as e:
        log_debug(f"Erro ao ler JSON: {e}")
        sys.exit(1)

    # 2. Extração do IP
    src_ip = alert_json.get("parameters", {}).get("alert", {}).get("data", {}).get("src_ip")
    if not src_ip:
        src_ip = alert_json.get("parameters", {}).get("alert", {}).get("data", {}).get("src_ip", None)
    
    if not src_ip:
        log_debug("Erro: IP de origem não encontrado")
        sys.exit(1)

    log_debug(f"Iniciando bloqueio para IP: {src_ip}")

    base_url = f"https://{PFSENSE_IP}/api/v2/firewall/aliases"
    apply_url = f"https://{PFSENSE_IP}/api/v1/firewall/apply" # Nota: Apply geralmente fica na v1 mesmo em installs v2
    
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }

    try:
        # 3. GET: Buscar alias atual
        r = requests.get(base_url, headers=headers, verify=False, timeout=10)
        
        if r.status_code != 200:
            log_debug(f"Erro no GET. Status: {r.status_code} Msg: {r.text}")
            sys.exit(1)

        aliases_list = r.json().get("data", [])
        target_alias = None
        
        for alias in aliases_list:
            if alias.get("name") == ALIAS_NAME:
                target_alias = alias
                break
        
        if not target_alias:
            log_debug(f"Erro: Alias '{ALIAS_NAME}' não encontrado!")
            sys.exit(1)

        # 4. Modificar a lista localmente
        current_ips = target_alias.get("address", [])
        if isinstance(current_ips, str):
            current_ips = [current_ips]
            
        if src_ip in current_ips:
            log_debug(f"IP {src_ip} já existe na lista. Nada a fazer.")
            sys.exit(0)
            
        current_ips.append(src_ip)
        target_alias["address"] = current_ips
        
        # 5. PUT: Enviar atualização (Array format)
        log_debug(f"Enviando atualização via PUT...")
        payload = [ target_alias ]
        
        r_update = requests.put(base_url, headers=headers, json=payload, verify=False, timeout=10)
        
        if r_update.status_code in [200, 201]:
            log_debug(f"Alias atualizado. Aplicando alterações no firewall...")
            
            # 6. APPLY: O Passo Final
            # Tenta aplicar na v1 (padrão do pacote)
            r_apply = requests.post(apply_url, headers=headers, json={}, verify=False, timeout=10)
            
            if r_apply.status_code == 200:
                log_debug("SUCESSO FINAL! Alterações aplicadas.")
                sys.exit(0)
            else:
                # Se falhar na v1, tenta na v2 (caso sua versão seja bleeding edge)
                log_debug(f"Apply v1 falhou ({r_apply.status_code}), tentando v2...")
                apply_url_v2 = f"https://{PFSENSE_IP}/api/v2/firewall/apply"
                r_apply_v2 = requests.post(apply_url_v2, headers=headers, json={}, verify=False, timeout=10)
                
                if r_apply_v2.status_code == 200:
                    log_debug("SUCESSO FINAL! Alterações aplicadas (v2).")
                    sys.exit(0)
                else:
                    log_debug(f"AVISO: IP Salvo, mas falha ao aplicar mudanças. Status: {r_apply_v2.status_code}")
                    sys.exit(0) # Sai com 0 pois o bloqueio foi salvo, só falta aplicar manual
        else:
            log_debug(f"FALHA ao salvar IP. Status: {r_update.status_code} | Msg: {r_update.text}")
            sys.exit(1)

    except Exception as e:
        log_debug(f"Erro critico: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
