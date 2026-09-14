FROM python:3.13-slim
WORKDIR /app
RUN useradd --uid 10001 --create-home aegis && mkdir /app/data && chown aegis:aegis /app/data
COPY --chown=aegis:aegis aegis /app/aegis
COPY --chown=aegis:aegis static /app/static
USER aegis
ENV AEGIS_HOST=0.0.0.0 AEGIS_DB=/app/data/aegis.db PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
CMD ["python", "-m", "aegis.server"]
