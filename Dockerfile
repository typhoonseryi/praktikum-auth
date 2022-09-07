FROM python:3.10

WORKDIR home/src/app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./flask_app .

RUN ["chmod", "+x", "./docker_entrypoint.sh"]
ENTRYPOINT ["./docker_entrypoint.sh"]