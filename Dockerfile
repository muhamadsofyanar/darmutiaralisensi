FROM python:3.12-slim
WORKDIR /opt/darmutiara
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system --gid 10001 darmutiara \
    && useradd --system --uid 10001 --gid 10001 darmutiara \
    && install -d -m 700 -o 10001 -g 10001 /data
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py activation.py ./
USER 10001:10001
EXPOSE 8000
CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:8000", "app:from_env()"]
