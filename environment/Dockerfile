FROM python:3.13-slim-bookworm
RUN pip install --no-cache-dir cryptography==46.0.4
WORKDIR /app
COPY data/ /app/data/
COPY service/ /app/service/
