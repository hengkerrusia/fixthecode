FROM python:3.12-alpine
RUN apk add --no-cache chromium
WORKDIR /srv
COPY render.py .
EXPOSE 8081
CMD ["python", "render.py"]
