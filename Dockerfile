FROM ubuntu:jammy AS python-builder

RUN apt-get update && \
    apt-get install -y python3 python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv && \
    /venv/bin/pip install -U pip setuptools

COPY requirements.txt /app/requirements.txt
RUN  /venv/bin/pip install --requirement /app/requirements.txt

COPY . /app
RUN /venv/bin/pip install /app


FROM ubuntu:jammy

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED 1

# Create the user that will be used to run the app
ENV APP_UID 1001
ENV APP_GID 1001
ENV APP_USER app
ENV APP_GROUP app
RUN groupadd --gid $APP_GID $APP_GROUP && \
    useradd \
      --no-create-home \
      --no-user-group \
      --gid $APP_GID \
      --shell /sbin/nologin \
      --uid $APP_UID \
      $APP_USER

RUN apt-get update && \
    apt-get install -y ca-certificates python3 tini && \
    rm -rf /var/lib/apt/lists/*

COPY --from=python-builder /venv /venv

USER $APP_UID
ENTRYPOINT ["tini", "-g", "--"]
CMD ["/venv/bin/kopf", "run", "--module", "capi_janitor.openstack.operator", "--all-namespaces"]
