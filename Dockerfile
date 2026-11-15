FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc libkrb5-dev krb5-user && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY netinv ./netinv
ENV NETINV_CONFIG=/app/config.toml
EXPOSE 8080
CMD ["python", "-m", "netinv", "serve", "--port", "8080"]
