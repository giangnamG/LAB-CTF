FROM node:20.6.0-alpine3.17@sha256:b46062adc42a16400adbc25c766966efee688ddd71ef315a5d333238c817dac8

RUN echo 'http://dl-cdn.alpinelinux.org/alpine/v3.9/main' >> /etc/apk/repositories
RUN echo 'http://dl-cdn.alpinelinux.org/alpine/v3.9/community' >> /etc/apk/repositories
RUN apk add --update --no-cache mongodb


RUN mkdir /app
WORKDIR /app
COPY Leak .

RUN npm install
COPY entrypoint.sh /entrypoint.sh
RUN chmod 777 /entrypoint.sh
COPY wait_for_mongo.js init_users.js /

EXPOSE 1773

RUN adduser \
    --disabled-password \
    --no-create-home \
    "mongo"

RUN adduser \
    --disabled-password \
    "isp"

ENV FLAG="ISPCTF{fake-flag}"
ENTRYPOINT /entrypoint.sh