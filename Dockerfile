FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home lab && mkdir /data && chown lab:lab /data
COPY --chown=lab:lab . .
USER lab
ENV LOG_LAB_DB_PATH=/data/analysis.db
EXPOSE 5000
CMD ["gunicorn", "--workers", "2", "--threads", "2", "--timeout", "120", "--bind", "0.0.0.0:5000", "app:app"]
