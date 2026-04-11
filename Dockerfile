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

# Run as UID/GID 53:53 so the container process has the same identity
# as BIND on the host. The read-only mounts of the key directory,
# named.log, and rndc.key are owned by that UID/GID on Peter's hosts,
# and writing to the events database volume must happen as 53:53 too.
# The numeric IDs are what actually matter — the name is "bind" purely
# for readability of `ps` output inside the container.
RUN groupadd --gid 53 bind \
    && useradd --uid 53 --gid 53 --no-create-home --shell /usr/sbin/nologin bind \
    && mkdir -p /var/lib/dnssec-tracker /etc/dnssec-tracker \
    && chown -R 53:53 /var/lib/dnssec-tracker

WORKDIR /opt/dnssec-tracker
COPY pyproject.toml README.md ./
COPY dnssec_tracker ./dnssec_tracker
COPY config ./config

RUN pip install --no-cache-dir .

USER bind
EXPOSE 8080
VOLUME ["/var/lib/dnssec-tracker"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "dnssec_tracker", "--config", "/etc/dnssec-tracker/dnssec-tracker.conf"]
