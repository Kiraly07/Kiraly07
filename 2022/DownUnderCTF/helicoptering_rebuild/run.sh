#!/bin/bash
docker build -t htaccess-bypass .
docker run -p 30026:80 htaccess-bypass

