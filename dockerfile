FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    software-properties-common \
    build-essential \
    libffi-dev \
    libssl-dev \
    zlib1g-dev \
    liblzma-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    curl \
    llvm \
    libncurses5-dev \
    xz-utils \
    tk-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libffi-dev \
    liblzma-dev

RUN curl -O https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tgz
RUN tar -xvf Python-3.11.0.tgz
RUN cd Python-3.11.0 && ./configure --enable-optimizations --enable-shared && make altinstall

ENV LD_LIBRARY_PATH /usr/local/lib:$LD_LIBRARY_PATH

RUN python3.11 -m pip install --upgrade pip
RUN python3.11 -m pip install pyinstaller
RUN python3.11 -m pip install cffi
RUN python3.11 -m pip install rich
RUN python3.11 -m pip install cryptography

COPY . /app
WORKDIR /app

RUN python3.11 modules/utils.py