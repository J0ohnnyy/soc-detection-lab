# Lab — build guide

Minimal, reproducible home SOC. Everything runs on a single host with a few VMs.

## Composants

| Rôle | Machine | Outils |
|---|---|---|
| SIEM | VM Linux (4 vCPU / 8 Go) | **Wazuh single-node** (indexer + dashboard) |
| Victime Windows | VM Windows 10/11 | **Sysmon** (config SwiftOnSecurity) + agent Wazuh |
| Victime Linux | VM Ubuntu | **auditd** + agent Wazuh |
| Attaquant | VM Kali | **Atomic Red Team** / Caldera |

> Réseau : un réseau **host-only / interne** isolé. Aucune technique offensive ne sort du lab.

## 1. Déployer Wazuh (single-node, Docker)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
# Dashboard : https://<ip-siem>  (admin / voir docker-compose)
```

## 2. Windows : Sysmon + agent

```powershell
# Sysmon avec une config de référence
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip ; Expand-Archive Sysmon.zip
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```
Puis installer l'**agent Wazuh** (MSI) et l'enrôler sur le manager. Vérifier que les EID Sysmon (1, 10, 13…) remontent dans le dashboard.

## 3. Linux : auditd + agent

```bash
sudo apt install -y auditd
sudo systemctl enable --now auditd
# installer l'agent Wazuh puis l'enrôler
```

## 4. Vérifier la télémétrie

Dans le dashboard Wazuh → *Security events* : tu dois voir les événements Sysmon (Windows) et auditd (Linux). Une fois les logs qui remontent, passe à [`../emulation/`](../emulation/).

## Checklist

- [ ] Wazuh dashboard accessible
- [ ] Agent Windows *Active*, EID Sysmon 1/10/13 visibles
- [ ] Agent Linux *Active*, événements auditd visibles
- [ ] Kali sur le réseau isolé, Atomic Red Team installé
