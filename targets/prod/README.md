# SNMP Project Production Deployment

## Prerequisites
- Docker and Docker Compose installed on the production server.
- Root or sudo access for port 162 (UDP) and firewall configuration.

## Steps
1. **Copy Files**
    - Transfer the `trapNode/` directory to the production server (e.g., via `scp`).
2. **Set Environment Variables**
    - Copy `.env.example` to `.env`.
    - Fill in values for `POSTGRES_PASSWORD`, `SNMP_AUTH_PASS`, `SNMP_PRIV_PASS`, `GRAFANA_ADMIN_PASSWORD`, etc.
    - Secure the file: `chmod 600 .env`
3. **Configure Firewall**
    - Allow UDP port 162 for SNMP traps: `sudo ufw allow 162/udp`
    - Allow TCP port 3000 for Grafana: `sudo ufw allow 3000/tcp`
4. **Load Images**
    - Run: `docker load -i images/snmptrapd.tar`
    - Run: `docker load -i images/trap-processor.tar`
    - Run: `docker load -i images/trap-sender.tar`
    - Run: `docker load -i images/postgres.tar`
    - Run: `docker load -i images/grafana.tar`
5. **Deploy**
    - Run: `docker-compose up -d`
6. **Verify**
    - Check logs: `docker-compose logs`
    - Access Grafana at `http://<server-ip>:3000` (login with admin/${GRAFANA_ADMIN_PASSWORD}).
    - Test SNMP traps with `trap-sender` or an external tool (e.g., `snmptrap`).
7. **Backup**
    - Regularly back up `postgres_data` and `grafana_data` volumes.
    - Example: `docker run --rm -v postgres_data:/data busybox tar cvf /backup/postgres_backup.tar /data`

## Notes
- Secure Grafana with HTTPS (e.g., via a reverse proxy like Nginx).
- Ensure no other process uses port 162 on the host.
- No internet access is required; all images are included as TAR files.