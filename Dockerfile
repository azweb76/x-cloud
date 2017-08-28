FROM centos:7

#RUN yum clean all
RUN yum install epel-release -y && \
  (yum install -y python2-pip && yum clean all)

WORKDIR /app/

COPY ./ ./
# RUN yum clean all
RUN yum install -y gcc python2-devel openssh-clients && \
   pip install ./ && \
   yum remove -y gcc python2-devel && yum clean all
