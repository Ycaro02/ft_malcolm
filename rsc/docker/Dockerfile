FROM ubuntu:24.04

RUN apt update && apt install -y wireshark iproute2 iputils-ping zsh clang make valgrind gdb curl git dnsutils netcat-traditional nmap libcriterion-dev libpcap-dev vim hping3

RUN apt install -y arping

ENV TZ=Europe/Paris
ENV EDITOR=/bin/vim

RUN git config --global --add safe.directory /app

RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# add basic alias for git
RUN echo 'alias add_all="git add . && git commit -m"' >> /root/.zshrc


