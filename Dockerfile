FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Non-root user: a security tool should not run as root
RUN useradd --create-home scanner && chown -R scanner /app
USER scanner
ENV DSSCAN_SALT=change-me-in-production
CMD ["sh", "-c", "python scripts/generate_data.py data && python -m dsscan.cli --data data --out reports"]
