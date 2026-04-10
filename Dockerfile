FROM python:3.12-slim

# System deps:
# - libpango-1.0-0, libpangoft2-1.0-0, libharfbuzz0b, libcairo2, libffi8, fonts:
#       required at runtime by WeasyPrint for PDF export
# - bind9-utils:
#       provides /usr/sbin/rndc for the rndc_status collector, which is
#       a first-class source for capturing BIND's "goal / dnskey / ds /
#       zone rrsig / key rrsig" key states
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9-utils \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libcairo2 \
        libffi8 \
        shared-mime-info \
        fonts-dejavu-core \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 5000 --home /var/lib/dnssec-tracker --shell /usr/sbin/nologin tracker \
    && mkdir -p /var/lib/dnssec-tracker /etc/dnssec-tracker \
    && chown -R tracker:tracker /var/lib/dnssec-tracker

WORKDIR /opt/dnssec-tracker
COPY pyproject.toml README.md ./
COPY dnssec_tracker ./dnssec_tracker
COPY config ./config

RUN pip install --no-cache-dir .

USER tracker
EXPOSE 8080
VOLUME ["/var/lib/dnssec-tracker"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "dnssec_tracker", "--config", "/etc/dnssec-tracker/dnssec-tracker.conf"]
