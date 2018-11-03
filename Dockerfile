FROM python:alpine
RUN pip install stem prometheus_client retrying
COPY ./prometheus-tor-exporter.py /prometheus-tor-exporter.py
WORKDIR /opt
EXPOSE 9051
ENTRYPOINT ["/usr/local/bin/python", "/prometheus-tor-exporter.py"]
