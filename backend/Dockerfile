FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY sample_logs ./sample_logs
ENV DATABASE_URL=sqlite:////data/horizon.db HORIZON_MODEL_PATH=/data/horizon_model.joblib
VOLUME /data
EXPOSE 8000
CMD ["sh", "-c", "mkdir -p /data && if [ \"$SEED_ON_START\" = \"true\" ]; then python -m app.seed --if-empty; fi && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
