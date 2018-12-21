FROM docker-registry.core.rcsops.com/coreservices/java:openjdk-8u92-jre-alpine-bash-openssl
# using below image while not connected to rcsnet
#FROM java:8-jre
ARG ARTIFACT
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
ENV PARTITIONLOC 'file:///data'
ENV USETLS 'false'
ENV USEVAULT 'false'
ENV VAULTURL 'http://vault:8200'
ENV TOKEN 'myroot'
ENV CONTEXTPATH 'secret/credentials'
ENV SAMPLETENANTS ''
ENV SAMPLECONNECTION ''
#rolodex jar version from mvn
ADD ${ARTIFACT} rolodex.jar
ADD config.yml.example config.yml
ADD adcert.jks adcert.jks
CMD java -Ddw.defaultConnector.hostname=${DEFAULT_HOST} -Ddw.defaultConnector.port=${DEFAULT_PORT} -Ddw.defaultConnector.username=${DEFAULT_USERNAME} -Ddw.defaultConnector.password=${DEFAULT_PASSWORD} -Ddw.defaultConnector.sourceTenantDn=${DEFAULT_SOURCETENANTDN} -Ddw.defaultConnector.ldapType=${DEFAULT_LDAPTYPE} -Ddw.defaultConnector.attributeMap=${DEFAULT_ATTRMAP} -Ddw.defaultConnector.readOnly=${DEFAULT_READONLY} -Ddw.maxRetries=${MAXRETRIES} -Ddw.partitionLoc=${PARTITIONLOC} -Ddw.transparentProxy=${TRANSPARENTPROXY}  -Ddw.useTls=${USETLS} -Ddw.useVault=${USEVAULT} -Ddw.vaultUrl=${VAULTURL} -Ddw.vaultToken=${TOKEN} -Ddw.remoteContextPath=${CONTEXTPATH}  -Ddw.sampleTenant=${SAMPLETENANTS}  -Ddw.sampeConnection=${SAMPLECONNECTION} -jar rolodex.jar server config.yml
EXPOSE 10389
EXPOSE 389
EXPOSE 11389
EXPOSE 9179
VOLUME /data


