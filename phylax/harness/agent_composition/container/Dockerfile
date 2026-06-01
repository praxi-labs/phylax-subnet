FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini ca-certificates docker.io \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /harness
COPY orchestrator.py /harness/orchestrator.py
COPY run.sh /harness/run.sh
RUN chmod +x /harness/run.sh

RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 1000 phylax \
 && mkdir -p /evidence \
 && chown phylax:phylax /evidence

USER phylax

ENTRYPOINT ["/usr/bin/tini", "--", "/harness/run.sh"]
