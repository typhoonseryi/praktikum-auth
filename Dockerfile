FROM python:3.10

WORKDIR home/src/app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./flask_app .

ENTRYPOINT ["bash", "docker_entrypoint.sh"]