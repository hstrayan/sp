FROM docker-registry.core.rcsops.com/coreservices/java:openjdk-8u92-jre-alpine-bash-openssl
# using below image while not connected to rcsnet
#FROM java:8-jre
MAINTAINER Harish S <harish.sathyanarayan@virtustream.com>
ARG ARTIFACT
ENV ROLODEX_JVM_OPT_ARGS ''
ENV CONNECTORS ''
ENV MAXRETRIES ''
ENV TRANSPARENTPROXY 'true'
ENV DEFAULT_HOST ''
ENV DEFAULT_PORT ''
ENV DEFAULT_USERNAME ''
ENV DEFAULT_PASSWORD ''
ENV DEFAULT_SOURCETENANTDN ''
ENV DEFAULT_LDAPTYPE ''
ENV DEFAULT_ATTRMAP ''
ENV DEFAULT_READONLY 'false'
# this URI can be localhost or URI path over network
ENV PARTITIONLOC 'file:///rolodex-data'
ENV USETLS ''
ENV CERTNAME ''
ENV CERTPWD ''
ENV USEVAULT 'false'
ENV VAULTURL 'http://vault:8200'
ENV TOKEN 'myroot'
ENV CONTEXTPATH 'secret/credentials'
ENV SAMPLETENANTS ''
ENV SAMPLECONNECTION ''
ENV DEFAULTADTENANTDN ''
ENV ISADREADONLY ''
ENV DEFAULTADCONSTR ''
#rolodex jar version from mvn
ADD ${ARTIFACT} rolodex.jar
RUN mkdir certs 
RUN mkdir config 
ADD config.yml.example config.yml
ADD server.ks server.ks
ADD ca.crt ca.crt
RUN chmod 777 ca.crt
ADD rolodex-entrypoint.sh /rolodex-entrypoint.sh
RUN chmod 777 /rolodex-entrypoint.sh
EXPOSE 10389
EXPOSE 389
EXPOSE 11389
EXPOSE 9179
EXPOSE 9999
VOLUME /data
ENTRYPOINT ["/bin/bash","/rolodex-entrypoint.sh"]


