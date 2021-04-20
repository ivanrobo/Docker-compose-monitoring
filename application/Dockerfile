FROM python:3.8-slim-buster
COPY requirements.txt requirements.txt
RUN apt-get update && apt-get install bash && apt-get install curl -y
RUN pip3 install -r requirements.txt
COPY . .
ENTRYPOINT ["./producer.sh"]
#CMD ["./sniff.py"]
