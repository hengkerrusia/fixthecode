FROM php:8.3-cli-alpine
COPY index.php /var/www/html/
COPY wp-admin/ /var/www/html/wp-admin/
COPY includes/ /var/www/html/includes/
COPY flag.txt /flag.txt
WORKDIR /var/www/html
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-d", "allow_url_include=On", "-t", "/var/www/html"]
