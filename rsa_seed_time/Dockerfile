FROM python:3.10.4

WORKDIR /app

COPY server.py /app

RUN pip install pycryptodome

EXPOSE 7777

CMD ["python", "server.py"]

# docker build -t rsa_seed .
# docker run --name=rsa_seed -d -p 7777:7777 rsa_seed
