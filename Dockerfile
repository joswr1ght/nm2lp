FROM ubuntu:14.04
MAINTAINER Alexandr Opryshko <sclif13@gmail.com>
ENV DEBIAN_FRONTEND noninteractive

RUN sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list

RUN apt-get update \
&& apt-get --yes build-dep wireshark \
&& apt-get --yes install qt5-default wget libwiretap3 dbus
# fixed url
RUN cd /tmp && wget https://1.na.dl.wireshark.org/src/all-versions/wireshark-1.12.4.tar.bz2 \
&& tar -xjf wireshark-1.12.4.tar.bz2 \
&& cd wireshark-1.12.4 \
&& ./configure && make -j 5 && make install

# install nm2lp deps (notice libwiretab downgrade)
RUN apt-get --yes install libwiretap-dev=1.10.6-1 libpcap-dev libwsutil-dev libgtk2.0-dev libglib2.0-dev

RUN dbus-uuidgen > /etc/machine-id && mkdir /pcap \
&& sed 's/dofile = function() error("dofile " .. hint) end//' /usr/local/share/wireshark/init.lua > /tmp/ddd \
&& mv /tmp/ddd /usr/local/share/wireshark/init.lua

RUN ldconfig
