#!/bin/bash

# Default platform (can be overridden with --platform argument)
PLATFORM="linux/amd64"
OFFLINE_MODE=true
VERSION=2.0.0
# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform=*) PLATFORM="${1#*=}"; shift ;;
        --online)     OFFLINE_MODE=false; shift ;;
        *)            echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# Configuration
DEV_DIR=$(pwd)
PROD_DIR="$DEV_DIR/prod"
mkdir -p "$PROD_DIR"

echo "Building offline deployment package for platform: $PLATFORM"

# Clean previous build
rm -rf "$PROD_DIR"/*
mkdir -p "$PROD_DIR"/{images,configs}

# 1. Package Docker Images =====================================================

echo "Saving required Docker images..."

    # List of all base images used
BASE_IMAGES=(
    postgres:15-alpine
    confluentinc/cp-zookeeper:7.4.0
    confluentinc/cp-kafka:7.4.0
    nginx:stable-alpine
    grafana/grafana:10.2.2
)

# Save all base images
for image in "${BASE_IMAGES[@]}"; do
    echo "Saving $image..."
    docker pull --platform $PLATFORM $image
    docker save $image -o "$PROD_DIR/images/$(echo $image | tr '/' '_' | tr ':' '_').tar"
done

# 2. Package Custom Services ==================================================
package_service() {
    local service_name=$1
    local context=$2
    local dockerfile="${3:-Dockerfile}"

    echo "Building and packaging $service_name image..."

    # Build the Docker image
    docker build \
        --platform=$PLATFORM \
        -t "dstp.docker/$service_name:$VERSION" \
        -f "$DEV_DIR/$context/$dockerfile" \
        "$DEV_DIR/$context"

    # Save the image to a tar file
    docker save "dstp.docker/$service_name:$VERSION" -o "$PROD_DIR/images/${service_name}_${VERSION}_image.tar"

    echo "Packaged $service_name image to $PROD_DIR/images/${service_name}_${VERSION}_image.tar"
}

# Package custom services
package_service "snmptrapd" "snmptrapd"
package_service "trap-processor" "trap-processor"
package_service "trap-sender" "trap-sender"

# 3. Package Configurations ===================================================
echo "Packaging configurations..."
mkdir -p "$PROD_DIR/configs"/{nginx,grafana,mibs,logs,postgres}

# Nginx
cp -r "$DEV_DIR/nginx"/* "$PROD_DIR/configs/nginx/"

# Grafana
cp -r "$DEV_DIR/grafana"/* "$PROD_DIR/configs/grafana/"

# Grafana
cp -r "$DEV_DIR/postgres"/* "$PROD_DIR/configs/postgres/"

# MIBs
[ -d "$DEV_DIR/mibs" ] && cp -r "$DEV_DIR/mibs"/* "$PROD_DIR/configs/mibs/"

# 4. Generate Deployment Files ================================================
cat > "$PROD_DIR/deploy.sh" <<'EOL'
#!/bin/bash

# Platform detection
if [ "$1" = "--platform" ]; then
    PLATFORM="$2"
    shift 2
else
    PLATFORM="linux/$(uname -m)"
fi

echo "=== OFFLINE DEPLOYMENT ==="
echo "Platform: $PLATFORM"

# 1. Load Docker Images
echo "Loading Docker images..."
for img in images/*.tar; do
    [ -f "$img" ] || continue
    echo "Loading $img..."
    docker load -i "$img"
done

# 3. Copy Configurations
echo "Setting up configurations..."
cp -r configs/nginx/* ./nginx/
cp -r configs/grafana/* ./grafana/
cp -r configs/mibs/* ./mibs/ 2>/dev/null || true
mkdir -p ./logs

# 4. Start the Stack
echo "Starting services..."
docker-compose up -d

echo "Deployment complete!"
EOL
chmod +x "$PROD_DIR/deploy.sh"

# 5. Generate docker-compose.yml =============================================
cat > "$PROD_DIR/docker-compose.yml" <<EOL
version: '3.8'

services:
  # Database
  snmp-psql:
    image: postgres:15-alpine
    container_name: snmp-postgres
    environment:
      POSTGRES_DB: \${POSTGRES_DB:-snmptraps}
      POSTGRES_USER: \${POSTGRES_USER:-snmpuser}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:-snmppass123}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./configs/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    ports:
      - "5432:5432"
    networks:
      - snmp-network

  # Kafka Ecosystem
  zookeeper:
    image: confluentinc/cp-zookeeper:7.4.0
    container_name: snmp-zookeeper
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - "2181:2181"
    networks:
      - snmp-network

  kafka:
    image: confluentinc/cp-kafka:7.4.0
    platform: $PLATFORM
    container_name: snmp-kafka
    depends_on:
      - zookeeper
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092
    ports:
      - "9092:9092"
    networks:
      - snmp-network

  # Monitoring
  grafana:
    image: grafana/grafana:latest
    container_name: snmp-grafana
    volumes:
      - grafana_data:/var/lib/grafana
      - ./configs/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./configs/grafana/dashboards:/var/lib/grafana/dashboards:ro
    ports:
      - "3000:3000"
    networks:
      - snmp-network

  nginx:
    image: nginx:stable-alpine
    container_name: snmp-nginx-lb
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    ports:
      - "162:162/udp"
    networks:
      - snmp-network
    depends_on:
      snmptrapd1:
        condition: service_started
      snmptrapd2:
        condition: service_started
      snmptrapd3:
        condition: service_started
      snmptrapd4:
        condition: service_started
      snmptrapd5:
        condition: service_started
      snmptrapd6:
        condition: service_started
      snmptrapd7:
        condition: service_started
      snmptrapd8:
        condition: service_started

  snmptrapd1:
    image: snmptrapd:2.0.0
    container_name: snmp-trapd-1
    ports:
      - "1162:162/udp"
    volumes:
      - ./logs:/var/log/snmp:z
      - ./mibs:/custom-mibs:ro
    environment:
      - MIBDIRS=/custom-mibs:/usr/share/snmp/mibs
      - MIBS=+ALL
      - SNMP_USER=${SNMP_USER:-snmpv3user}
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
      - SNMP_ENGINE=${SNMP_ENGINE:-0x8000000001020304}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      trap-processor:
        condition: service_started
    healthcheck:
      test: ["CMD", "pgrep", "snmptrapd"]
      interval: 30s
      timeout: 10s
      retries: 3

  snmptrapd2:
    image: snmptrapd:2.0.0
    container_name: snmp-trapd-2
    ports:
      - "1262:162/udp"
    volumes:
      - ./logs:/var/log/snmp:z
      - ./mibs:/custom-mibs:ro
    environment:
      - MIBDIRS=/custom-mibs:/usr/share/snmp/mibs
      - MIBS=+ALL
      - SNMP_USER=${SNMP_USER:-snmpv3user}
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
      - SNMP_ENGINE=${SNMP_ENGINE:-0x8000000001020304}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      trap-processor:
        condition: service_started
    healthcheck:
      test: [ "CMD", "pgrep", "snmptrapd" ]
      interval: 30s
      timeout: 10s
      retries: 3

  snmptrapd3:
    image: snmptrapd:2.0.0
    container_name: snmp-trapd-3
    ports:
      - "1362:162/udp"
    volumes:
      - ./logs:/var/log/snmp:z
      - ./mibs:/custom-mibs:ro
    environment:
      - MIBDIRS=/custom-mibs:/usr/share/snmp/mibs
      - MIBS=+ALL
      - SNMP_USER=${SNMP_USER:-snmpv3user}
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
      - SNMP_ENGINE=${SNMP_ENGINE:-0x8000000001020304}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      trap-processor:
        condition: service_started
    healthcheck:
      test: [ "CMD", "pgrep", "snmptrapd" ]
      interval: 30s
      timeout: 10s
      retries: 3

  snmptrapd4:
    image: snmptrapd:2.0.0
    container_name: snmp-trapd-4
    ports:
      - "1462:162/udp"
    volumes:
      - ./logs:/var/log/snmp:z
      - ./mibs:/custom-mibs:ro
    environment:
      - MIBDIRS=/custom-mibs:/usr/share/snmp/mibs
      - MIBS=+ALL
      - SNMP_USER=${SNMP_USER:-snmpv3user}
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
      - SNMP_ENGINE=${SNMP_ENGINE:-0x8000000001020304}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      trap-processor:
        condition: service_started
    healthcheck:
      test: [ "CMD", "pgrep", "snmptrapd" ]
      interval: 30s
      timeout: 10s
      retries: 3

  snmptrapd5:
    image: snmptrapd:2.0.0
    container_name: snmp-trapd-5
    ports:
      - "1562:162/udp"
    volumes:
      - ./logs:/var/log/snmp:z
      - ./mibs:/custom-mibs:ro
    environment:
      - MIBDIRS=/custom-mibs:/usr/share/snmp/mibs
      - MIBS=+ALL
      - SNMP_USER=${SNMP_USER:-snmpv3user}
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
      - SNMP_ENGINE=${SNMP_ENGINE:-0x8000000001020304}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      trap-processor:
        condition: service_started
    healthcheck:
      test: [ "CMD", "pgrep", "snmptrapd" ]
      interval: 30s
      timeout: 10s
      retries: 3

  snmptrapd6:
    image: snmptrapd:2.0.0
    container_name: snmp-trapd-6
    ports:
      - "1662:162/udp"
    volumes:
      - ./logs:/var/log/snmp:z
      - ./mibs:/custom-mibs:ro
    environment:
      - MIBDIRS=/custom-mibs:/usr/share/snmp/mibs
      - MIBS=+ALL
      - SNMP_USER=${SNMP_USER:-snmpv3user}
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
      - SNMP_ENGINE=${SNMP_ENGINE:-0x8000000001020304}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      trap-processor:
        condition: service_started
    healthcheck:
      test: [ "CMD", "pgrep", "snmptrapd" ]
      interval: 30s
      timeout: 10s
      retries: 3

  snmptrapd7:
    image: snmptrapd:2.0.0
    container_name: snmp-trapd-7
    ports:
      - "1762:162/udp"
    volumes:
      - ./logs:/var/log/snmp:z
      - ./mibs:/custom-mibs:ro
    environment:
      - MIBDIRS=/custom-mibs:/usr/share/snmp/mibs
      - MIBS=+ALL
      - SNMP_USER=${SNMP_USER:-snmpv3user}
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
      - SNMP_ENGINE=${SNMP_ENGINE:-0x8000000001020304}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      trap-processor:
        condition: service_started
    healthcheck:
      test: [ "CMD", "pgrep", "snmptrapd" ]
      interval: 30s
      timeout: 10s
      retries: 3

  snmptrapd8:
    image: snmptrapd:2.0.0
    container_name: snmp-trapd-8
    ports:
      - "1862:162/udp"
    volumes:
      - ./logs:/var/log/snmp:z
      - ./mibs:/custom-mibs:ro
    environment:
      - MIBDIRS=/custom-mibs:/usr/share/snmp/mibs
      - MIBS=+ALL
      - SNMP_USER=${SNMP_USER:-snmpv3user}
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
      - SNMP_ENGINE=${SNMP_ENGINE:-0x8000000001020304}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      trap-processor:
        condition: service_started
    healthcheck:
      test: [ "CMD", "pgrep", "snmptrapd" ]
      interval: 30s
      timeout: 10s
      retries: 3

  trap-processor:
    build:
      context: trap-processor:2.0.0
    container_name: snmp-processor
    volumes:
      - ./logs:/app/logs:z
    environment:
      # PostgreSQL configuration
      - DB_HOST=snmp-psql
      - DB_PORT=5432
      - DB_NAME=${POSTGRES_DB:-snmptraps}
      - DB_USER=${POSTGRES_USER:-snmpuser}
      - DB_PASSWORD=${POSTGRES_PASSWORD:-snmppass}
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
      - KAFKA_BROKER=${KAFKA_BROKER:-kafka:9092}
      - KAFKA_TOPIC=${KAFKA_TOPIC:-snmp_traps}
    networks:
      - snmp-network
    depends_on:
      snmp-psql:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "python", "-c", "import psycopg2; psycopg2.connect(host='snmp-psql', database='${POSTGRES_DB:-snmptraps}', user='${POSTGRES_USER:-snmpuser}', password='${POSTGRES_PASSWORD:-snmppass}')"]
      interval: 30s
      timeout: 10s
      retries: 3



volumes:
  postgres_data:
  grafana_data:

networks:
  snmp-network:
    driver: bridge
EOL

# 6. Create Final Package ====================================================
echo "Creating final deployment package..."
tar -czf "$DEV_DIR/DSTP-2.0.0-${PLATFORM//\//.}.tar.gz" -C "$PROD_DIR" .

echo "============================================"
echo "OFFLINE DEPLOYMENT PACKAGE CREATED SUCCESSFULLY"
echo "File: $DEV_DIR/DSTP-2.0.0-${PLATFORM//\//.}.tar.gz"
echo ""
echo "To deploy on target VM:"
echo "1. Copy the tar file to the VM"
echo "2. Run:"
echo "   tar -xzf DSTP-2.0.0-${PLATFORM//\//.}.tar.gz"
echo "   cd prod"
echo "   ./deploy.sh"
echo "============================================"