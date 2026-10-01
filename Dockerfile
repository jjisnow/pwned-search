FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY pwned.py .
USER 65534:65534
ENTRYPOINT ["python", "/app/pwned.py"]
