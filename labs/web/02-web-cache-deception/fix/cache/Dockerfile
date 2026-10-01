FROM python:3.12-alpine
WORKDIR /srv
COPY cache.py .
ENV LISTEN_PORT=80 APP_HOST=app APP_PORT=8000
EXPOSE 80
CMD ["python", "cache.py"]
