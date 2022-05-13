FROM debian:bullseye-slim

ARG DEBIAN_FRONTEND=noninteractive
ENV LC_ALL C

# Add groups and users before installing Postfix to not break compatibility
RUN apt-get update && apt-get install -y --no-install-recommends \
	python3 \
	python3-pip \
	python3-setuptools \
	&& rm -rf /var/lib/apt/lists/* \
	&& touch /etc/default/locale

RUN pip3 install wheel
RUN pip3 install fuglu==0.10.8 caldav==0.9.0 icalendar==4.0.9

COPY fuglu_logging.conf /etc/fuglu/logging.conf
COPY fuglu_caldav_plugin.py /usr/local/fuglu/plugins/calendar_caldav.py
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN rm -rf /tmp/* /var/tmp/*

EXPOSE 8894

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD exec /usr/local/bin/fuglu --foreground
