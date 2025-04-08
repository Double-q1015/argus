# 基础镜像
FROM ubuntu:20.04 as base

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# 设置DNS
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf
RUN echo "nameserver 114.114.114.114" >> /etc/resolv.conf

# 设置代理
ENV http_proxy=http://192.168.2.2:7890
ENV https_proxy=http://192.168.2.2:7890
ENV HTTP_PROXY=http://192.168.2.2:7890
ENV HTTPS_PROXY=http://192.168.2.2:7890

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    wget \
    git \
    curl \
    vim \
    htop \
    net-tools \
    iputils-ping \
    telnet \
    dnsutils \
    netcat \
    tcpdump \
    lsof \
    procps \
    sudo \
    build-essential \
    libssl-dev \
    libffi-dev \
    pkg-config \
    # YARA 依赖
    automake \
    libtool \
    libjansson-dev \
    libmagic-dev \
    libssl-dev \
    yara \
    && rm -rf /var/lib/apt/lists/*

# 配置 git 使用代理
RUN git config --global http.proxy http://192.168.2.2:7890 && \
    git config --global https.proxy http://192.168.2.2:7890
