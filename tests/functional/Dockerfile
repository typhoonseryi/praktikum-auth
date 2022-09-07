FROM python:3.10

WORKDIR /tests/functional

ENV PYTHONPATH .

COPY ./requirements.txt .
RUN pip install -r requirements.txt --no-warn-script-location

RUN useradd -m tests
USER tests

COPY . .
