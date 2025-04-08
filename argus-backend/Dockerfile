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
ENV http_proxy=http://192.168.2.9:7890
ENV https_proxy=http://192.168.2.9:7890
ENV HTTP_PROXY=http://192.168.2.9:7890
ENV HTTPS_PROXY=http://192.168.2.9:7890

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
RUN git config --global http.proxy http://192.168.2.9:7890 && \
    git config --global https.proxy http://192.168.2.9:7890

# 安装 Miniconda
FROM base as conda
RUN wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh && \
    bash /tmp/miniconda.sh -b -p /opt/conda && \
    rm /tmp/miniconda.sh

# 设置 Conda 环境
ENV PATH="/opt/conda/bin:$PATH"
ENV CONDA_PREFIX=/opt/conda
ENV CONDA_DEFAULT_ENV=base
ENV CONDA_EXE=/opt/conda/bin/conda
ENV CONDA_PYTHON_EXE=/opt/conda/bin/python
ENV CONDA_SHLVL=1
ENV CONDA_PROMPT_MODIFIER=(base)
ENV CONDA_ENV_PATH=/opt/conda

# 初始化 conda
RUN /opt/conda/bin/conda init bash && \
    echo "conda activate base" >> ~/.bashrc

# 配置 conda
RUN conda config --set always_yes yes && \
    conda config --add channels conda-forge && \
    conda config --set channel_priority strict

# 创建 Conda 环境
RUN conda create -n argus python=3.10 && \
    echo "conda activate argus" >> ~/.bashrc

# 安装 Python 依赖
FROM conda as python-deps
WORKDIR /home/ubuntu
COPY argus-backend/requirements.txt /tmp/requirements.txt
RUN conda activate argus && \
    pip install -r /tmp/requirements.txt

# 最终镜像
FROM conda
COPY --from=python-deps /opt/conda/envs/argus /opt/conda/envs/argus

# 设置工作目录
WORKDIR /home/ubuntu

# 设置 LD_LIBRARY_PATH
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
