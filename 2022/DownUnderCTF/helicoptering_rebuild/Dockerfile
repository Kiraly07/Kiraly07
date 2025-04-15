FROM php:7.4-apache

# Enable mod_rewrite
RUN a2enmod rewrite

# Copy Apache conf
COPY default.conf /etc/apache2/sites-available/000-default.conf

# Copy source
COPY ./ /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html

EXPOSE 80

