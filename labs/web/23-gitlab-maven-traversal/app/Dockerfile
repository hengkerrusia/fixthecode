FROM python:3.12-alpine
WORKDIR /app
COPY server.py /app/
RUN mkdir -p /data/packages /data/.ssh \
    && echo "# placeholder - do not remove" > /data/.ssh/authorized_keys \
    && chmod 755 /data /data/packages /data/.ssh \
    && chmod 644 /data/.ssh/authorized_keys
EXPOSE 8080
CMD ["python3", "server.py"]
