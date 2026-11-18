# FASE 1 (vulnerable): corre como root, con el servidor de desarrollo de Flask en modo debug
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
