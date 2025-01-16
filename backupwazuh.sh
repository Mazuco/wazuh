#!/bin/bash
# backupwazuh.sh
#################### SCRIPT PARA BACKUP DO WAZUH SERVER ####################
# Vitor Mazuco <contato@vmzsolutions.com.br>                             #
# Created Jan, 2025                                                     ##

# Criando um diretório para backup:
bkp_folder=~/wazuh_files_backup/$(date +%F_%H:%M)
mkdir -p $bkp_folder && echo $bkp_folder

# Salve as informações do host:
cat /etc/*release* > $bkp_folder/host-info.txt
echo -e "\n$(hostname): $(hostname -I)" >> $bkp_folder/host-info.txt

# Faça backup dos dados e arquivos de configuração do servidor Wazuh:

rsync -aREz \
/etc/filebeat/ \
/etc/postfix/ \
/var/ossec/api/configuration/ \
/var/ossec/etc/client.keys \
/var/ossec/etc/sslmanager* \
/var/ossec/etc/ossec.conf \
/var/ossec/etc/internal_options.conf \
/var/ossec/etc/local_internal_options.conf \
/var/ossec/etc/rules/local_rules.xml \
/var/ossec/etc/decoders/local_decoder.xml \
/var/ossec/etc/shared/ \
/var/ossec/logs/ \
/var/ossec/queue/agentless/ \
/var/ossec/queue/agents-timestamp \
/var/ossec/queue/fts/ \
/var/ossec/queue/rids/ \
/var/ossec/stats/ \
/var/ossec/var/multigroups/ $bkp_folder

# Se houver, faça backup dos certificados e arquivos de configuração adicionais:
rsync -aREz \
/var/ossec/etc/*.pem \
/var/ossec/etc/authd.pass $bkp_folder

# Faça backup dos seus arquivos personalizados. Se você tiver respostas ativas personalizadas, listas de CDB, integrações ou wodles, adapte o comando a seguir adequadamente:

rsync -aREz \
/var/ossec/active-response/bin/* \
/var/ossec/etc/lists/*.cdb \
/var/ossec/integrations/* \
/var/ossec/wodles/* $bkp_folder

# Agora, vamos fazer uma rápida parada do sistema para o backup:

systemctl stop wazuh-manager

# Faça backup dos bancos de dados Wazuh. Eles contêm dados coletados de agentes.

rsync -aREz \
/var/ossec/queue/db/ $bkp_folder

# Agora, vamos religar o daemon:

systemctl start wazuh-manager

# Fazendo backup do indexador e do painel do Wazuh

# Faça backup dos certificados e arquivos de configuração do indexador do Wazuh.

rsync -aREz \
/etc/wazuh-indexer/certs/ \
/etc/wazuh-indexer/jvm.options \
/etc/wazuh-indexer/jvm.options.d \
/etc/wazuh-indexer/log4j2.properties \
/etc/wazuh-indexer/opensearch.yml \
/etc/wazuh-indexer/opensearch.keystore \
/etc/wazuh-indexer/opensearch-observability/ \
/etc/wazuh-indexer/opensearch-reports-scheduler/ \
/etc/wazuh-indexer/opensearch-security/ \
/usr/lib/sysctl.d/wazuh-indexer.conf $bkp_folder

# Faça backup dos certificados e arquivos de configuração do painel do Wazuh.

rsync -aREz \
/etc/wazuh-dashboard/certs/ \
/etc/wazuh-dashboard/opensearch_dashboards.yml \
/usr/share/wazuh-dashboard/config/opensearch_dashboards.keystore \
/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml $bkp_folder

# Se tiver, faça backup de seus downloads e imagens personalizadas.

rsync -aREz \
/usr/share/wazuh-dashboard/data/wazuh/downloads/ \
/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom/images/ $bkp_folder

# Por fim, vamos remover os backups antigos, e sempre deixando os últimos 10 dias

TIME="+10"

find ~/wazuh_files_backup/ -ctime +10 -exec rm {} \;

exit 0
