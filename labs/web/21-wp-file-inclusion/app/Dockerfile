FROM python:3.12-alpine
WORKDIR /app
COPY . /app
RUN mkdir -p /app/theme/page-templates \
    && chmod 755 /app /app/theme /app/theme/page-templates /app/secret \
    && chmod 644 /app/secret/db-backup.php /app/theme/page.php \
       /app/theme/style.css /app/server.py
EXPOSE 8080
CMD ["python3", "server.py"]
