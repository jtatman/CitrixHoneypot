FROM python:3.12-slim
LABEL maintainer="Bontchev"
LABEL name="CitrixHoneypot"
LABEL version="2.0.2"

# Unprivileged user; listen on a high port so no extra capabilities are needed.
# Map it to 443 on the host/lab network with `-p 443:8443`.
RUN useradd --system --create-home --home-dir /CitrixHoneypot honeypot
WORKDIR /CitrixHoneypot
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=honeypot:honeypot . .
USER honeypot
ENV HONEYPOT_LISTEN_PORT=8443
EXPOSE 8443
# Mount your key.pem/cert.pem at /CitrixHoneypot/ssl
CMD [ "python", "./CitrixHoneypot.py" ]
