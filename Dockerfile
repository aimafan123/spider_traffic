FROM 192.168.194.63:5000/ubuntu:latest

# 设置工作目录
WORKDIR /app
# 安装chrome浏览器和驱动已经相关依赖
RUN apt update
RUN apt install -y \
    fonts-liberation    \
    libatk-bridge2.0-0  \
    libatk1.0-0 \
    libatspi2.0-0   \
    libcairo2   \
    libcups2    \
    libdrm2 \
    libgbm1 \
    libgtk-3-0  \
    libnspr4    \
    libnss3 \
    libpango-1.0-0  \
    libu2f-udev \
    libvulkan1  \
    libxcomposite1  \
    libxdamage1 \
    libxfixes3  \
    libxkbcommon0   \
    libxrandr2  \
    libevent-dev \
    xdg-utils   

# 安装基本工具和依赖
# RUN sed -i 's|http://deb.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list && \
RUN    apt-get update && apt-get install -y \
    vim \
    sudo \
    python3.12 \
    python3-pip \
    python3.12-venv \
    net-tools \
    wget    \
    curl    \
    build-essential \
    gcc \
    make \
    inetutils-ping \
    python-is-python3 \
    cmake \
    libboost-date-time-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libssl-dev \
    zlib1g-dev \
    debhelper \
    fakeroot \
    devscripts \
    dh-apparmor \
    ethtool \
    libpcap-dev \
    tcpdump \
    libevent-dev \
    tshark

# 将vim设为默认编辑器
RUN update-alternatives --set editor /usr/bin/vim.basic

# 想要把.venv目录忽略，单独创建.dockerignore文件，然后写入.venv
ADD . .
# 取消网卡合并包，需要在启动容器之后跑
# RUN sudo ethtool -K eth0 tso off gso off gro off
RUN python -m venv .venv
RUN . .venv/bin/activate && pip3 install --no-cache-dir -r requirements.txt


RUN sudo apt install -y libasound2t64
RUN sudo dpkg -i bin/google-chrome-stable_current_amd64.deb
RUN sudo apt install -f
RUN sudo dpkg -i bin/google-chrome-stable_current_amd64.deb
RUN sudo mv bin/chromedriver-linux64/chromedriver /usr/bin


# 默认命令，打开vim
CMD ["bash"]
