FROM python:3.12-alpine
WORKDIR /srv
COPY app.py .
ENV LISTEN_PORT=8000 TRUSTED_CIDR=10.201.0.0/16
EXPOSE 8000
CMD ["python", "app.py"]
