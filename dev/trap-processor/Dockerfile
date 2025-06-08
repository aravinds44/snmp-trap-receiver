FROM python:3.10-slim

# Create app user
RUN useradd -m -u 1001 appuser

# Set working directory
WORKDIR /app

# Create MIB directories and set permissions
RUN mkdir -p /app/logs

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY trap_processor.py .
COPY config.py .

# Set proper permissions
RUN chown -R appuser:appuser /app && \
    chmod +x /app/trap_processor.py

# Switch to app user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import psycopg2; psycopg2.connect(host='${DB_HOST}', database='${DB_NAME}', user='${DB_USER}', password='${DB_PASSWORD}')" || exit 1

# Start the trap processor
CMD ["python", "trap_processor.py"]