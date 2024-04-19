FROM python:3.10.4

WORKDIR /app

COPY server.py /app

RUN pip install pycryptodome

EXPOSE 7777

CMD ["python", "server.py"]

# docker build -t rsa_oracle .
# docker run --name=rsa_oracle -d -p 7778:7777 rsa_oracle
