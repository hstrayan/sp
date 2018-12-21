# Rolodex
Rolodex
-----------

ROLODEX is a Virtual Directory Engine Microservice. It acts as a Proxy and facade for LDAP operations exposed via a REST Interface. These
LDAP operations may be performed against external/remote LDAP based directory services like Active Directories, OpenLDAP based services etc.
Thus it provides an unified interface for set of operations performed across LDAP services hosted in datacenters or otherwise. It addresses many
of the usecases defined here http://myvd.sourceforge.net/

Unified Profile Access and Administration - Abstracts multiple disparate DNs into a unified View/Access. Ease of use for Administrators.

Delegated Authentication - Uses concept of ProxyConnectors to handle all authentication to remote directory services

Leverage ApacheDS Interceptors - Based on rules and mapping defined, will use appropriate interceptors to trigger and forward requests

Ease of deployment and Scalability - Goal is to make this Microservice easily configurable for end-users to quickly deploy in their envrironments.
Metrices on scalability/performance to be provided.

Interceptors:

ApacheDS has functional layers in its design called Interceptors. These internal components are designed to perform a specific task. They are ordered
and chained and order cannot be broken as per the ApacheDS architecture. they do allow for custom interceptors to be written and injected
into the chain to perform specific operation. Rolodex implements custom interceptors. All interceptors extend BaseInterceptor class.

Connectors:

Rolodex provides custom Connectors (implements connector interface) to perform tasks like authentication to remote services among others.
There can be more than one connector per interceptor. These are configurable and instantiated during app engine load time. Currently all connectors
support LDAP protocol only though other protocols can be incorporated.

Interceptor-Connector Mapping:

These are configurable components which contain the mapping of connectors to interceptors.

App Engine: 

This runs the embedded ApacheDS instance. Partitions, Schemas/DIT structures are configurable during loadtime. 

Dropwizard:

Rolodex uses dropwizard framework for REST API and other relevant features.

Deploying and running Rolodex:

1. Build Dockerfile
   docker build -t <tagname> .
2. run 'docker images' to verify image exists
3. run below command:
   docker run -p 9179:9179 -p 9180:9180 <tagname>
4. run 'docker ps' to verify running container
5. open up a browser and go to 'http://<ip address>:9179/rolodex/health' to check the health of the running services.
   All services (embeded and external sources) should be running fine. Rolodex will not work correctly if any of them are   
   not running correctly. 





#   s t u f f  
 #   l p r x  
 #   s p  
 