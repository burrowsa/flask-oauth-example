FROM ubuntu:14.04
RUN apt-get update && apt-get install -y python3 python3-dev python3-pip
COPY ./requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY ./templates /flask-oauth-example/templates
COPY ./app.py /flask-oauth-example/app.py
COPY ./oauth.py /flask-oauth-example/oauth.py
WORKDIR /flask-oauth-example
ENTRYPOINT ["python3", "-m", "app"]
EXPOSE 5000
