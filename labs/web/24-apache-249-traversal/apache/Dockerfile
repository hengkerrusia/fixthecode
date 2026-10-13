FROM httpd:2.4.49
COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY htdocs/ /usr/local/apache2/htdocs/
COPY cgi-bin/ /usr/local/apache2/cgi-bin/
RUN mkdir -p /usr/local/apache2/icons \
    && chmod +x /usr/local/apache2/cgi-bin/hello.sh
