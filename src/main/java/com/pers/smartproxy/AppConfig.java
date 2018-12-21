package com.pers.smartproxy;

import java.util.Collections;
import java.util.Map;

import javax.validation.Valid;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableMap;
import com.pers.smartproxy.representations.ConnectorInfo;
import com.pers.smartproxy.representations.ProxyConfiguration;

import io.dropwizard.Configuration;
import io.dropwizard.db.DataSourceFactory;

/**
 * @author sathyh2
 *
 *         Defines a set of configuration for Virtual Directory Services
 * 
 */

public class AppConfig extends Configuration {

	/**
	 * use hashicorp vault - yes/no
	 */
	private boolean useVault;
	/**
	 * use hashicorp vault - yes/no
	 */
	private String vaultUrl;
	/**
	 * vault token
	 */
	private String vaultToken;

	/**
	 * local context path
	 */
	private String localContextPath;

	/**
	 * remote context path
	 */
	private String remoteContextPath;

	/**
	 * use TLS Handler to start TLS session
	 */
	private boolean useTls;
	/**
	 * port number
	 */
	@Min(389)
	private int port;
	/**
	 * SSL port number
	 */
	private int sslPort;
	/**
	 * is SSL? true/false
	 */
	private boolean isSSL;
	/**
	 * Host Name - Localhost(default)
	 */
	private String hostName;
	/**
	 * IP Address
	 */
	private String serverAddress;
	/**
	 * User Name
	 */
	private String localUserName;
	/**
	 * Password
	 */
	private String localPasswd;
	/**
	 * certificate keystore name
	 */
	private String certName;
	/**
	 * certificate password
	 */
	private String certPwd;
	/**
	 * changelogs to be enabled/disabled
	 */
	private boolean changeLog;
	/**
	 * custom partition
	 */
	private boolean useCustomPartition;
	/**
	 * define partition name
	 */
	private String partitionName;
	/**
	 * partition location
	 */
	private String partitionLoc;
	/**
	 * array of indexes that need to be added
	 */
	private String[] indexAttrs;
	/**
	 * external connectors
	 */
	private ConnectorInfo defaultConnector;
	/**
	 * num of cached entries
	 */
	private int cachedEntries;
	/**
	 * parent Node
	 */
	private String parentNode;
	/**
	 * schema file name
	 */
	private String schemaFileName;
	/**
	 * define interceptors
	 */
	private String interceptor;
	/**
	 * define connectors
	 */
	private String connector;
	/**
	 * define service name
	 */
	private String serviceName;
	/**
	 * number of threads to create in the acceptor
	 */
	private int nbThreads;
	/**
	 * queue size for incoming messages, waiting for the acceptor to be ready
	 */
	private int backlog;

	/**
	 * load the connector configurations
	 */

	private Map<String, Map<String, String>> defaultConnectorConfiguration = Collections.emptyMap();
	/**
	 * load the connector operations
	 */
	private Map<String, Map<String, String>> defaultConnectorOperations = Collections.emptyMap();
	/**
	 * Failover configurations
	 */
	private Map<String, Map<String, String>> failOverConnectorConfiguration = Collections.emptyMap();

	/**
	 * is transparent proxy used?
	 */
	private boolean transparentProxy;
	/**
	 * tenancy Dn
	 */
	private String tenancyDn;
	/**
	 * mapping Dn
	 */
	private String mappingDn;
	/**
	 * schema filter
	 */
	private String schemaFilter;
	/**
	 * rolodex attrs
	 */
	private String[] rolodexAttrs;
	/**
	 * proxy attributes object store
	 */
	private Map<String, ProxyConfiguration> tenantMappingReqs;
	
    private String[] sampleTenant;
	
	private String sampeConnection;
	
	private int maxRetries;
	
	private ConnectorInfo failoverConnector;
	
	private String[] connectors;
	
	private String defaultADTenantDn;
	
	private boolean isAdReadyOnly;
	
	private String defaultADconnStr;
	
	
	/**
	 * no-args constructor
	 */
	public AppConfig() {
	}

	/**
	 * @return
	 */
	public boolean isUseVault() {
		return useVault;
	}

	/**
	 * @param useVault
	 */
	public void setUseVault(boolean useVault) {
		this.useVault = useVault;
	}

	/**
	 * @return String
	 */
	public String getVaultUrl() {
		return vaultUrl;
	}

	/**
	 * @param vaultUrl
	 */
	public void setVaultUrl(String vaultUrl) {
		this.vaultUrl = vaultUrl;
	}

	/**
	 * @return
	 */
	public String getVaultToken() {
		return vaultToken;
	}

	/**
	 * @param vaultToken
	 */
	public void setVaultToken(String vaultToken) {
		this.vaultToken = vaultToken;
	}

	/**
	 * @return
	 */
	public String getLocalContextPath() {
		return localContextPath;
	}

	/**
	 * @param localContextPath
	 */
	public void setLocalContextPath(String localContextPath) {
		this.localContextPath = localContextPath;
	}

	/**
	 * @return
	 */
	public String getRemoteContextPath() {
		return remoteContextPath;
	}

	/**
	 * @param remoteContextPath
	 */
	public void setRemoteContextPath(String remoteContextPath) {
		this.remoteContextPath = remoteContextPath;
	}

	/**
	 * check if TLS used?
	 * 
	 * @return
	 */
	public boolean isUseTls() {
		return useTls;
	}

	/**
	 * use TLS
	 * 
	 * @param useTls
	 */
	public void setUseTls(boolean useTls) {
		this.useTls = useTls;
	}

	/**
	 * port number getter
	 * 
	 * @return int
	 */
	public int getPort() {
		return port;
	}

	/**
	 * port number setter
	 * 
	 * @param port
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * @return int
	 */
	public int getSslPort() {
		return sslPort;
	}

	/**
	 * @param sslPort
	 */
	public void setSslPort(int sslPort) {
		this.sslPort = sslPort;
	}

	/**
	 * @return
	 */
	public boolean isSSL() {
		return isSSL;
	}

	/**
	 * @param isSSL
	 */
	public void setSSL(boolean isSSL) {
		this.isSSL = isSSL;
	}

	/**
	 * hostname getter
	 * 
	 * @return String
	 */
	public String getHostName() {
		return hostName;
	}

	/**
	 * hostname setter
	 * 
	 * @param hostName
	 */
	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	/**
	 * IP address getter
	 * 
	 * @return String
	 */
	public String getServerAddress() {
		return serverAddress;
	}

	/**
	 * IP Address setter
	 * 
	 * @param serverAddress
	 */
	public void setServerAddress(String serverAddress) {
		this.serverAddress = serverAddress;
	}

	/**
	 * @return
	 */
	public String getLocalUserName() {
		return localUserName;
	}

	/**
	 * @param localUserName
	 */
	public void setLocalUserName(String localUserName) {
		this.localUserName = localUserName;
	}

	/**
	 * @return String
	 */
	public String getLocalPasswd() {
		return localPasswd;
	}

	/**
	 * @param localPasswd
	 */
	public void setLocalPasswd(String localPasswd) {
		this.localPasswd = localPasswd;
	}

	/**
	 * @return String
	 */
	public String getCertName() {
		return certName;
	}

	/**
	 * @param certName
	 */
	public void setCertName(String certName) {
		this.certName = certName;
	}

	/**
	 * @return String
	 */
	public String getCertPwd() {
		return certPwd;
	}

	/**
	 * @param certPwd
	 */
	public void setCertPwd(String certPwd) {
		this.certPwd = certPwd;
	}

	/**
	 * changelog getter
	 * 
	 * @return boolean
	 */
	public boolean isChangeLog() {
		return changeLog;
	}

	/**
	 * changelog setter
	 * 
	 * @param changeLog
	 */
	public void setChangeLog(boolean changeLog) {
		this.changeLog = changeLog;
	}

	/**
	 * @return
	 */
	public boolean isUseCustomPartition() {
		return useCustomPartition;
	}

	/**
	 * @param useCustomPartition
	 */
	public void setUseCustomPartition(boolean useCustomPartition) {
		this.useCustomPartition = useCustomPartition;
	}

	/**
	 * add partitions getter
	 * 
	 * @return String[]
	 */
	public String getPartitionName() {
		return partitionName;
	}

	/**
	 * add partitions setter
	 * 
	 * @param partition
	 */
	public void setPartitionName(String partitionName) {
		this.partitionName = partitionName;
	}

	/**
	 * get partition location
	 * 
	 * @return
	 */
	public String getPartitionLoc() {
		return partitionLoc;
	}

	/**
	 * set partition location
	 * 
	 * @param partitionLoc
	 */
	public void setPartitionLoc(String partitionLoc) {
		this.partitionLoc = partitionLoc;
	}

	/**
	 * get array of indexes
	 * 
	 * @return String[]
	 */
	public String[] getIndexAttrs() {
		return indexAttrs;
	}

	/**
	 * set array of indexes
	 * 
	 * @param indexAttrs
	 */
	public void setIndexAttrs(String[] indexAttrs) {
		this.indexAttrs = indexAttrs;
	}

	/**
	 * @return String[]
	 */
	public ConnectorInfo getDefaultConnector() {
		return defaultConnector;
	}

	/**
	 * @param connectors
	 */
	public void setDefaultConnector(ConnectorInfo defaultConnector) {
		this.defaultConnector = defaultConnector;
	}
	/**
	 * get cached entries
	 * @return int
	 */
	public int getCachedEntries() {
		return cachedEntries;
	}

	/**
	 * @param cachedEntries
	 */
	public void setCachedEntries(int cachedEntries) {
		this.cachedEntries = cachedEntries;
	}
	/**
	 * get parent node
	 * 
	 * @return String
	 */
	public String getParentNode() {
		return parentNode;
	}

	/**
	 * set parent node
	 * 
	 * @param parentNode
	 */
	public void setParentNode(String parentNode) {
		this.parentNode = parentNode;
	}

	/**
	 * get schema filename
	 * 
	 * @return String
	 */
	public String getSchemaFileName() {
		return schemaFileName;
	}

	/**
	 * assign schema file name
	 * 
	 * @param schemaFileName
	 */
	public void setSchemaFileName(String schemaFileName) {
		this.schemaFileName = schemaFileName;
	}

	/**
	 * interceptors getter
	 * 
	 * @return String[]
	 */
	public String getInterceptor() {
		return interceptor;
	}

	/**
	 * adding interceptors setter
	 * 
	 * @param interceptor
	 */
	public void setInterceptor(String interceptor) {
		this.interceptor = interceptor;
	}

	/**
	 * connectors getter
	 * 
	 * @return String[]
	 */
	public String getConnector() {
		return connector;
	}

	/**
	 * adding connectors setter
	 * 
	 * @param connector
	 */

	public void setConnector(String connector) {
		this.connector = connector;
	}

	/**
	 * get service name
	 * 
	 * @return String
	 */
	public String getServiceName() {
		return serviceName;
	}

	/**
	 * service name
	 * 
	 * @param String
	 *            serviceName
	 */
	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
	}

	/**
	 * The number of threads to create in the acceptor
	 * 
	 * @return int
	 */
	public int getNbThreads() {
		return nbThreads;
	}

	/**
	 * setting number of threads to create in the acceptor
	 * 
	 * @param int
	 */
	public void setNbThreads(int nbThreads) {
		this.nbThreads = nbThreads;
	}

	/**
	 * The queue size for incoming messages, waiting for the acceptor to be
	 * ready
	 * 
	 * @return int
	 */
	public int getBacklog() {
		return backlog;
	}

	/**
	 * setting queue size for incoming messages, waiting for the acceptor to be
	 * ready
	 * 
	 * @param int
	 */
	public void setBacklog(int backlog) {
		this.backlog = backlog;
	}

	/**
	 * get connector configuration
	 * 
	 * @return Map<String, Map<String, String>>
	 */

	public Map<String, Map<String, String>> getDefaultConnectorConfiguration() {
		return defaultConnectorConfiguration;
	}

	/**
	 * set the connector configurations
	 * 
	 * @param defaultConnectorConfiguration
	 */
	public void setDefaultConnectorConfiguration(Map<String, Map<String, String>> defaultConnectorConfiguration) {
		final ImmutableMap.Builder<String, Map<String, String>> builder = ImmutableMap.builder();
		for (Map.Entry<String, Map<String, String>> entry : defaultConnectorConfiguration.entrySet()) {
			builder.put(entry.getKey(), ImmutableMap.copyOf(entry.getValue()));
		}
		this.defaultConnectorConfiguration = builder.build();
	}

	/**
	 * get connector operations
	 * 
	 * @return Map<String, Map<String, String>>
	 */
	public Map<String, Map<String, String>> getDefaultConnectorOperations() {
		return defaultConnectorOperations;
	}

	/**
	 * set the connector operations
	 * 
	 * @param defaultConnectorOperations
	 */
	public void setDefaultConnectorOperations(Map<String, Map<String, String>> defaultConnectorOperations) {
		final ImmutableMap.Builder<String, Map<String, String>> builder = ImmutableMap.builder();
		for (Map.Entry<String, Map<String, String>> entry : defaultConnectorOperations.entrySet()) {
			builder.put(entry.getKey(), ImmutableMap.copyOf(entry.getValue()));
		}
		this.defaultConnectorOperations = builder.build();
	}

	/**
	 * @return Map<String, Map<String, String>>
	 */
	public Map<String, Map<String, String>> getFailOverConnectorConfiguration() {
		return failOverConnectorConfiguration;
	}

	/**
	 * @param failOverConnectorConfiguration
	 */
	public void SetFailOverConnectorConfiguration(Map<String, Map<String, String>> failOverConnectorConfiguration) {
		final ImmutableMap.Builder<String, Map<String, String>> builder = ImmutableMap.builder();
		for (Map.Entry<String, Map<String, String>> entry : failOverConnectorConfiguration.entrySet()) {
			builder.put(entry.getKey(), ImmutableMap.copyOf(entry.getValue()));
		}
		this.failOverConnectorConfiguration = builder.build();
	}

	/**
	 * @return boolean
	 */
	public boolean isTransparentProxy() {
		return transparentProxy;
	}

	/**
	 * @param isTransparentProxy
	 */
	public void setTransparentProxy(boolean transparentProxy) {
		this.transparentProxy = transparentProxy;
	}

	/**
	 * @return String
	 */
	public String getTenancyDn() {
		return tenancyDn;
	}

	/**
	 * @param tenancyDn
	 */
	public void setTenancyDn(String tenancyDn) {
		this.tenancyDn = tenancyDn;
	}

	/**
	 * @return String
	 */
	public String getMappingDn() {
		return mappingDn;
	}

	/**
	 * @param mappingDn
	 */
	public void setMappingDn(String mappingDn) {
		this.mappingDn = mappingDn;
	}

	/**
	 * @return String
	 */
	public String getSchemaFilter() {
		return schemaFilter;
	}

	/**
	 * @param schemaFilter
	 */
	public void setSchemaFilter(String schemaFilter) {
		this.schemaFilter = schemaFilter;
	}

	/**
	 * @return
	 */
	public String[] getRolodexAttrs() {
		return rolodexAttrs;
	}

	/**
	 * @param rolodexAttrs
	 */
	public void setRolodexAttrs(String[] rolodexAttrs) {
		this.rolodexAttrs = rolodexAttrs;
	}


	/**
	 * @return Map<String, ProxyConfiguration>
	 */
	public Map<String, ProxyConfiguration> getTenantMappingReqs() {
		return tenantMappingReqs;
	}

	/**
	 * @param tenantMappingReqs
	 */
	public void setTenantMappingReqs(Map<String, ProxyConfiguration> tenantMappingReqs) {
		this.tenantMappingReqs = tenantMappingReqs;
	}

	/**
	 * @return String
	 */
	public String[] getSampleTenant() {
		return sampleTenant;
	}

	/**
	 * @param sampleTenant
	 */
	public void setSampleTenant(String[] sampleTenant) {
		this.sampleTenant = sampleTenant;
	}

	/**
	 * @return String
	 */
	public String getSampeConnection() {
		return sampeConnection;
	}

	/**
	 * @param sampeConnection
	 */
	public void setSampeConnection(String sampeConnection) {
		this.sampeConnection = sampeConnection;
	}
	
	/**
	 * @return
	 */
	public int getMaxRetries() {
		return maxRetries;
	}

	/**
	 * @param maxRetries
	 */
	public void setMaxRetries(int maxRetries) {
		this.maxRetries = maxRetries;
	}
	
	/**
	 * @return ConnectorInfo
	 */
	public ConnectorInfo getFailoverConnector() {
		return failoverConnector;
	}

	/**
	 * @param failoverConnector
	 */
	public void setFailoverConnector(ConnectorInfo failoverConnector) {
		this.failoverConnector = failoverConnector;
	}
	
	public String[] getConnectors() {
		return connectors;
	}

	public void setConnectors(String[] connectors) {
		this.connectors = connectors;
	}
	
	public String getDefaultADTenantDn() {
		return defaultADTenantDn;
	}

	public void setDefaultADTenantDn(String defaultADTenantDn) {
		this.defaultADTenantDn = defaultADTenantDn;
	}

	public boolean getIsAdReadyOnly() {
		return isAdReadyOnly;
	}

	public void setIsAdReadyOnly(boolean isAdReadyOnly) {
		this.isAdReadyOnly = isAdReadyOnly;
	}

	public String getDefaultADconnStr() {
		return defaultADconnStr;
	}

	public void setDefaultADconnStr(String defaultADconnStr) {
		this.defaultADconnStr = defaultADconnStr;
	}
	
	 @Valid
	    @NotNull
	    @JsonProperty("database")
	    private DataSourceFactory database = new DataSourceFactory();

	    public DataSourceFactory getDatabaseAppDataSourceFactory() {
	        return database;
	    }
}
