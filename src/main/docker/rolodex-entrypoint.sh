#!/bin/bash
#cp /etc/rolodex-certs/ca.crt /certs/ca.crt
cp ca.crt /certs/ca.crt
cp config.yml /config/config.yml
keytool -noprompt -storepass rolodex -import -alias ad -keystore adcert.jks -file /certs/ca.crt
java ${ROLODEX_JVM_OPT_ARGS} -Ddw.defaultConnector.hostname=${DEFAULT_HOST} -Ddw.defaultConnector.port=${DEFAULT_PORT} -Ddw.defaultConnector.username=${DEFAULT_USERNAME} -Ddw.defaultConnector.password=${DEFAULT_PASSWORD} -Ddw.defaultConnector.sourceTenantDn=${DEFAULT_SOURCETENANTDN} -Ddw.defaultConnector.ldapType=${DEFAULT_LDAPTYPE} -Ddw.defaultConnector.attributeMap=${DEFAULT_ATTRMAP} -Ddw.defaultConnector.readOnly=${DEFAULT_READONLY} -Ddw.maxRetries=${MAXRETRIES} -Ddw.partitionLoc=${PARTITIONLOC} -Ddw.transparentProxy=${TRANSPARENTPROXY}  -Ddw.useTls=${USETLS} -Ddw.certName=${CERTNAME} -Ddw.certPwd=${CERTPWD} -Ddw.vaultUrl=${VAULTURL} -Ddw.vaultToken=${TOKEN} -Ddw.remoteContextPath=${CONTEXTPATH}  -Ddw.sampleTenant=${SAMPLETENANTS}  -Ddw.sampeConnection=${SAMPLECONNECTION} -Ddw.defaultADTenantDn=${DEFAULTADTENANTDN} -Ddw.isAdReadyOnly=${ISADREADONLY} -Ddw.defaultADconnStr=${DEFAULTADCONSTR} -Ddw.connectors=${CONNECTORS} -jar rolodex.jar server /config/config.yml
