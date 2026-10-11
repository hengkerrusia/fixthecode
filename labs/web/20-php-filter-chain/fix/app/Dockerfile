# Debian-based (bukan alpine): rantai filter php://filter butuh tabel
# iconv glibc yang lengkap; iconv musl/alpine tidak cukup.
FROM php:8.3-cli
WORKDIR /var/www/html
COPY . /var/www/html
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/var/www/html"]
