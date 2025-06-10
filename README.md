# SNMP Trap Receiver System

A production-ready, modular SNMP Trap Receiver system designed for high-throughput environments. This architecture captures SNMPv3 traps, resolves OIDs using custom MIBs, publishes parsed data to Kafka, and stores it in a PostgreSQL database with Grafana for real-time observability.

---
## 🧩 Architecture Overview

```text
           ┌──────────────┐
           │ SNMP Devices │
           └──────┬───────┘
                  │ Traps (UDP 162)
           ┌──────▼───────┐
           │   NGINX LB   │
           └──────┬───────┘
      ┌───────────┴────────────┐
      │  Multiple snmptrapd    │  ← AuthPriv SNMPv3, custom MIBs
      └───────────┬────────────┘
                  │ JSON
              ┌───▼───┐
              │ Kafka │  ← Topic: `snmp_traps`
              └───┬───┘
                  │
           ┌──────▼──────┐
           │ Trap Parser │  ← Parses trap and inserts to DB
           └──────┬──────┘
                  │ SQL
            ┌─────▼─────┐
            │ PostgreSQL│  ← Structured trap storage
            └─────┬─────┘
                  │
           ┌──────▼──────┐
           │   Grafana   │  ← Real-time dashboards
           └─────────────┘
```
## 📦 Features

- 📜 Custom MIB/OID Resolution
Dynamically resolves OIDs into meaningful names using /custom-mibs.
- 🔁 Kafka Streaming Pipeline
Decouples trap ingestion and processing using Apache Kafka.
- 🧠 Trap Processor Microservice
Subscribes to Kafka, parses trap data, and stores it into PostgreSQL.
- 📊 Grafana Dashboards
Out-of-the-box dashboard support for visualizing SNMP traps in real time.
- 🐳 Docker-Compose Deployment
Easily spin up the full stack with a single command.

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- SNMPv3-compatible trap sender
- Custom MIBs (if applicable)

## Run the Stack
```shell
git clone https://github.com/yourorg/snmp-trap-receiver.git
cd snmp-trap-receiver/src

# Start the stack
docker-compose up -d --build
```

## 🔐 SNMPv3 Configuration
Ensure your devices send SNMPv3 traps using the following credentials:
```text
Username      : ${SNMP_USERNAME}
Auth Protocol : SHA
Auth Password : ${SNMP_AUTH_PASS}
Priv Protocol : AES
Priv Password : ${SNMP_PRIV_PASS}
```

## 📁 Directory Structure
```text
.
├── snmptrapd/                 
│   └── snmptrapd.conf         
├── trap-processor/           
│   └── app.py
├── db/
│   └── init.sql              
├── grafana/
│   ├── provisioning/
│   └── dashboards/
├── nginx/
│   └── nginx.conf            
├── .env.example              
└── docker-compose.yml        
```
## 📊 Grafana Dashboards

- URL: http://localhost:3000
- Default credentials: admin / admin123
- Preconfigured PostgreSQL data source and dashboards.

## ⚙️ Extensibility

- Add new snmptrapd instances by cloning the container block in docker-compose.yml.
- Extend the trap processor logic for:
  - Alerting
  - Correlation
  - Export to external systems
## 🧪 Testing Traps

Use snmptrap to simulate trap events:
```shell
snmptrap -v3 -u $USER -l authPriv -a SHA -A $AUTH -x AES -X $PRIV \
  127.0.0.1:$PORT '' .1.3.6.1.4.1.8072.2.3.0.1
```

## 🙋 Support

For issues or contributions, please open a GitHub issue or pull request.