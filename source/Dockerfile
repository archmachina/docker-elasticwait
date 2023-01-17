FROM docker.io/python:3.11.1-bullseye

ARG DEBIAN_FRONTEND=noninteractive

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY wait.py /wait.py

ENTRYPOINT [ "python3", "/wait.py" ]
