FROM python:3.10.4

WORKDIR /app

COPY server.py /app

RUN pip install pycryptodome


EXPOSE 7777

CMD ["python", "server.py"]

# docker build -t sha256_chall .
# docker run --name=sha256_chall -d -p 7779:7777 sha256_chall
