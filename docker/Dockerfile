FROM	debian:12.14-slim

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive \
	apt-get install --no-install-recommends --assume-yes \
	wget \
	software-properties-common \
	build-essential \
	valgrind \
	python3

COPY ./inetutils-2.0.tar.gz /

RUN tar -xf inetutils-2.0.tar.gz && cd inetutils-2.0 \
	&& ./configure --prefix=/usr --localstatedir=/var \
	&& make && make install && cd .. \
	&& rm -rf inetutils-2.0.tar.gz && rm -rf inetutils-2.0


RUN mkdir -p ft_ping

RUN wget https://apt.llvm.org/llvm.sh \
 && chmod +x llvm.sh && ./llvm.sh 22 \
 && ln -s /usr/bin/clang-22 /usr/bin/clang

RUN adduser dev --no-create-home --disabled-password

CMD ["bash"]
