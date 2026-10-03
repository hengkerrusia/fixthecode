FROM python:3.12-alpine
WORKDIR /app
COPY proxy.py chunked.py ./
ENV PORT=80 BACKEND_HOST=backend BACKEND_PORT=8000
EXPOSE 80
CMD ["python", "proxy.py"]
