FROM alpine:3.19.1

ADD bin/cloud-provisioner.tar.gz /CTS/resources/

RUN chmod -R 0700 /CTS/resources/bin/cloud-provisioner

CMD ["bash"]