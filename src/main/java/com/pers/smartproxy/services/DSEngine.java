package com.pers.smartproxy.services;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.factory.DefaultDirectoryServiceFactory;
import org.apache.directory.server.core.factory.DirectoryServiceFactory;
import org.apache.directory.server.core.partition.impl.avl.AvlPartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.CertGenerationRequestHandler;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pers.smartproxy.AppConfig;
import com.pers.smartproxy.connectors.DefaultProxyConnector;
import com.pers.smartproxy.connectors.EmbeddedConnector;
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.interceptors.ProxyInterceptor;
import com.pers.smartproxy.interceptors.TenancyInterceptor;
import com.pers.smartproxy.representations.AttributeTypeEntryFilter;
import com.pers.smartproxy.representations.ConnectorInfo;
import com.pers.smartproxy.representations.Enums;
import com.pers.smartproxy.representations.ProxyConfiguration;
import com.pers.smartproxy.representations.RolodexVault;
import com.pers.smartproxy.utils.LdapCrudUtils;

/**
 * @author sathyh2
 * 
 *         Embedded Apache DS Instance.
 *
 */

public class DSEngine {
	final Logger logger = LoggerFactory.getLogger(DSEngine.class);

	/**
	 * schema dir
	 */
	private static final String DIRNAME = "Rolodex";
	/**
	 * objectclass of type Organization
	 */
	private static final String ORGANIZATIONOBJ = "objectClass: organization";
	/**
	 * objectclass of type TOP
	 */
	private static final String TOPOBJ = "objectClass: top";
	/**
	 * proxy interceptor class
	 */
	private ProxyInterceptor proxyInterceptor = null;
	/**
	 * apacheds directory service
	 */
	private DirectoryService service = null;
	/**
	 * apacheds coresession
	 */
	private CoreSession dsSession = null;
	/**
	 * ldap server
	 */
	private LdapServer ldapServer = null;
	/**
	 * map of connectors
	 */
	private Map<String, ProxyConnector> connectors = new ConcurrentHashMap<>();
	/**
	 * map of rolodex handlers
	 */
	private Map<String, ProxyConfiguration> handlers = new ConcurrentHashMap<>();
	/**
	 * list of ldap nodes
	 */
	private List<org.apache.directory.api.ldap.model.entry.Entry> nodes = Collections
			.synchronizedList(new ArrayList<org.apache.directory.api.ldap.model.entry.Entry>());
	/**
	 * connector name
	 */
	private String connectorName;
	/**
	 * ProxyConnector class
	 */
	private ProxyConnector connector;

	/**
	 * LdapConnectionPool
	 */
	private LdapConnectionPool pool;

	/**
	 * InputStream
	 */
	private InputStream inputStream;

	/**
	 * EmbeddedConnector
	 */
	private EmbeddedConnector embeddedConnector;

	/**
	 * organixational unit
	 */
	private static final String ORGOBJCLS = "objectClass: organizationalUnit";
	/**
	 * tenancy object class
	 */
	private static final String TENANCYOBJCLS = "objectClass: tenancy";
	/**
	 * top object class
	 */
	private static final String TOPOBJCLS = "objectClass: top";

	private TenancyInterceptor tenancyInterceptor = null;
	
	private ConcurrentHashMap<String,org.apache.directory.api.ldap.model.entry.Entry> tenants = 
			new ConcurrentHashMap<String,org.apache.directory.api.ldap.model.entry.Entry>();

	JdbmPartition partition = null;

	private AppConfig config;

	private boolean isFullyLoaded = false;

	private ConnectorInfo defaultConnector;

	

	/**
	 * no-args constructor
	 * 
	 * @throws Exception
	 */
	public DSEngine() {
	}

	/**
	 * Starts services based on the configuration settings.
	 * 
	 * @param AppConfig
	 * @throws Exception
	 */
	public DSEngine(AppConfig configuration) {
		this.config = configuration;
		// Initialize the LDAP service
		DirectoryServiceFactory directoryServiceFactory = new DefaultDirectoryServiceFactory();
		try {
			directoryServiceFactory.init(DIRNAME + new Random().nextInt(50) + 1);
			service = directoryServiceFactory.getDirectoryService();

			service.setShutdownHookEnabled(true);
			dsSession = service.getSession();
			partition = new JdbmPartition(service.getSchemaManager(), service.getDnFactory());
			Entry entry = new DefaultEntry();
			entry.setDn(new Dn(configuration.getPartitionName()));
			entry.add("objectClass", "organizationalUnit", "top");
			partition.setContextEntry(entry);
			partition.setId(DIRNAME);
			partition.setSuffixDn(new Dn(configuration.getPartitionName()));
			partition.setCacheSize(1000);
			partition.setPartitionPath(new URI(configuration.getPartitionLoc()));
		} catch (Exception e) {
			logger.info("partition cannot be created for: " + configuration.getPartitionName() + " already exists");
		//	System.exit(0);
		}
		// ldapserver connection
		ldapServer = new LdapServer();
		// if using TLS
		if (configuration.isUseTls()) {
			try {
				useTLS(configuration);
			} catch (Exception e) {
				logger.debug("useTLS exception" + e);
			}
		}
		if (configuration.getServerAddress() != null) {
			TcpTransport transport = new TcpTransport(configuration.getServerAddress(), configuration.getPort());
			
			transport.setEnableSSL(true);
			ldapServer.setTransports(transport);
		} else { // assume it is localhost, just need a port to bind
			System.out.println("run ssl mode");
			TcpTransport transport = new TcpTransport(10636);
			System.out.println("4");
		
			System.out.println("5");
			
			System.out.println("1");
			ldapServer.setKeystoreFile("zanzibar.ks");
			System.out.println("2");
			ldapServer.setCertificatePassword("secret");
//			try {
//				ldapServer.loadKeyStore();
//			} catch (Exception e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
			transport.setEnableSSL(true);
			ldapServer.setTransports(transport);
		
		} 
		ldapServer.setDirectoryService(service);
		try {
		
			service.startup();
			ldapServer.start();
			if (configuration.isUseCustomPartition()) {
				createEmbeddedConnection(configuration);
				restoreCustomLDif(configuration);
			}
			System.out.println("Rolodex started on port: " + configuration.getPort() + " and running fine!!");
		} catch (Exception e) {
			logger.info("..erroring out" + e);
		}
		try {
			if (!getEmbedPool().getConnection().exists(new Dn(configuration.getPartitionName()))) {
			
				service.addPartition(partition);
				partition.initialize();
			}
			createTenantStructure();
			
			List<ConnectorInfo> connectorInfos = new ArrayList<ConnectorInfo>();
			if (configuration.getDefaultConnector() != null) {
				connectorInfos.add(configuration.getDefaultConnector());
			}
			if ((configuration.getConnectors() != null && configuration.getConnectors().length > 0)) {
				String[] ctrs = configuration.getConnectors();	
				for (String ctr : ctrs) {
					ConnectorInfo connectorInfo  = new ConnectorInfo();
					if (ctr != null && ctr.length() > 0) {
						String[] ctrParams = ctr.split(":");
						connectorInfo.setHostname(ctrParams[0]);
						connectorInfo.setPort(Integer.parseInt(ctrParams[1]));
						connectorInfo.setUsername(ctrParams[2]);
						connectorInfo.setPassword(ctrParams[3]);
						if (ctrParams[4] != null && !ctrParams[4].equalsIgnoreCase("false")){
							//set SSL
							connectorInfo.setUseTLS(true);
							connectorInfo.setKeyStorePath(ctrParams[5]);
							connectorInfo.setKeyStorePwd(ctrParams[6]);
						}
						if (!ctrParams[8].equalsIgnoreCase("false")){
							connectorInfo.setLdapType(ctrParams[7]);
							logger.debug("Default is AD");
							connectorInfo.setIsDefault("true");
							setDefaultConnector(connectorInfo);
							}
						else {
							logger.debug("Default is OPENLDAP");
							
						}
					
					}
					connectorInfos.add(connectorInfo);					
				}
			}
			loadDockerConnectors(connectorInfos);
			loadAllTenantConnectors();
			ConnectorInfo defaultConn = getDefaultConnector();
			if (defaultConn != null && defaultConn.getLdapType().equalsIgnoreCase("AD")) {
				ProxyConnector connection = connectors.get(defaultConn.getHostname());
				EntryCursor cursor = connection.getPool().getConnection().search(config.getDefaultADTenantDn(),
						"(objectclass=*)", SearchScope.ONELEVEL);
				while (cursor.next()) {
					logger.debug("entry is " + cursor.get().getDn().getName());
					String[] keyArray = cursor.get().getDn().getName().split(",");
					String[] keys = keyArray[0].split("=");
					if (!keys[1].equalsIgnoreCase("tenants") && !keys[1].equalsIgnoreCase("virtustream")) {
						if (!tenants.containsKey(keys[1])) {
							syncMissingEntries(keys);
						}
					}
				}
			}
			tenancyInterceptor = new TenancyInterceptor(configuration, service, getAllTenants(),getDefaultConnector());
			tenancyInterceptor.setConnectorMap(this.connectors);
			service.addFirst(tenancyInterceptor);	     
		} catch (Exception e) {
			logger.info("expection: " + e);
			try {
				recoverSchemaAfterFailure(configuration);
			} catch (Exception e1) {
				logger.info("expection: " + e);
			}
		}
	}

	private void syncMissingEntries(String[] keys) throws LdapInvalidDnException, LdapException {
		logger.debug("does not contain "+keys[1]);
		Entry notFoundEntry =  new DefaultEntry();
		String dn = "ou=".concat(keys[1]).concat(",ou=tenants,o=emc");
		notFoundEntry.setDn(dn);
		notFoundEntry.add("objectClass", "tenancy", "organizationalUnit", "top");
		notFoundEntry.add("sourceTenantDn",config.getDefaultADTenantDn());
		notFoundEntry.add("ldapType","AD");
		String connStr;
		if (config.getDefaultADconnStr().contains("%20")){
			connStr = config.getDefaultADconnStr().replace("%20", " ");
		} else connStr = config.getDefaultADconnStr();
		notFoundEntry.add("connectionString",connStr);
		notFoundEntry.add("attrsMap","uid=cn,userPassword=UnicodePwd");
		String firstPart = LdapCrudUtils.getFirstPartDn(dn);
		String sourceUsersDn = "ou=users,".concat(firstPart).concat(",").concat(config.getDefaultADTenantDn());
		notFoundEntry.add("sourceUsersDn",sourceUsersDn);
		notFoundEntry.add("readOnly","true");
		notFoundEntry.add("tenantName",keys[1]);
		notFoundEntry.add("tenantDomain",keys[1]);
		notFoundEntry.add("TENANTID","unknown");
		notFoundEntry.add("resourcesetid","unknown");
		
		Entry ou =  new DefaultEntry();
		String ouDn = "ou=users,ou=".concat(keys[1]).concat(",ou=tenants,o=emc");
		ou.setDn(ouDn);
		ou.add("objectClass", "tenancy", "organizationalUnit", "top");
		
		tenants.put(keys[1], notFoundEntry);
		getEmbedPool().getConnection().add(notFoundEntry);
		getEmbedPool().getConnection().add(ou);
	}



	/**
	 * @param configuration
	 * @throws Exception
	 * @throws LdapException
	 */
	private void recoverSchemaAfterFailure(AppConfig configuration) throws Exception, LdapException {
		partition.repair();
		service.addPartition(partition);
		partition.initialize();
		tenancyInterceptor = new TenancyInterceptor(configuration, this.service, getAllTenants(), getDefaultConnector());
		
		tenancyInterceptor.setConnectorMap(this.connectors);
		service.addFirst(tenancyInterceptor);
	}

	/**
	 * Load all Docker config for connectors
	 * 
	 * @param ctrs
	 * 
	 */
	private void loadDockerConnectors(List<ConnectorInfo> connectorInfos) {
		for (ConnectorInfo connectorInfo : connectorInfos) {
			try {
				bootstrapConnections(connectors, connectorInfo.getHostname(), connectorInfo);
			} catch (Exception e) {
				logger.info("connection lost for " + connectorInfo.getHostname());
			}
		}
	}

	
	/**
	 * load all tenant connectors
	 */
	protected void loadAllTenantConnectors() {
		try {
			LdapConnection embedConnection = getEmbedPool().getConnection();
			EntryCursor cursor = embedConnection.search("ou=tenants,o=emc", "(objectclass=*)", SearchScope.ONELEVEL);
			while (cursor.next()) {
				org.apache.directory.api.ldap.model.entry.Entry entry = cursor.get();
				AttributeTypeEntryFilter.SetAttributeTypes(entry);
				String dn = entry.getDn().getName();
				String tenant = LdapCrudUtils.getTenantNameFromDn(dn);
				tenants.put(tenant, entry);
				if (entry.containsAttribute(Enums.CustomAttributes.CONNECTIONSTRING.toString())) {
					Attribute connectionAttr = entry.get(Enums.CustomAttributes.CONNECTIONSTRING.toString());
					String connStr = connectionAttr.getString();
					String host = getHostNameOrIP(connStr);
					if (host != null && !getConnectors().containsKey(host)) {
//						if (!entry.containsAttribute(Enums.CustomAttributes.SOURCETENANTDN.toString()))
//							// TODO Add Message
//							throw new LdapException();
//						if (!entry.containsAttribute(Enums.CustomAttributes.SOURCEUSERSDN.toString()))
//							// TODO Add Message
//							throw new LdapException();
//						if (!entry.containsAttribute(Enums.CustomAttributes.LDAPTYPE.toString()))
//							// TODO Add Message
//							throw new LdapException();
//						if (!entry.containsAttribute(Enums.CustomAttributes.READONLY.toString()))
//							// TODO Add Message
//							throw new LdapException();

						ConnectorInfo connectorInfo = new ConnectorInfo(connStr);
						connectorInfo.setSourceTenantDn(
								entry.get(Enums.CustomAttributes.SOURCETENANTDN.toString()).toString());
						connectorInfo.setSourceUsersDn(
								entry.get(Enums.CustomAttributes.SOURCEUSERSDN.toString()).toString());
						connectorInfo.setLdapType(entry.get(Enums.CustomAttributes.LDAPTYPE.toString()).toString());
						connectorInfo.setReadOnly(
								Boolean.parseBoolean(entry.get(Enums.CustomAttributes.READONLY.toString()).toString()));
						
//						if (connectorInfo.isUseTLS()){
//							//connectorInfo.
//						}
                        try{
						ProxyConnector connector = bootstrapConnectionsForTenant(connectorInfo);
						logger.info("adding host " + host);
						getConnectors().put(host, connector);
                        }catch(Exception e){
                        	System.out.println("disconnected***********");
                        	logger.debug(e.getMessage());
                        }
					}
				}
			}
			logger.debug("size of connectors is " + getConnectors().size());
		} catch (CursorException | LdapException e) {
			logger.debug(e.getMessage());
		}
	}

	/**
	 * create tenant structure
	 */
	private void createTenantStructure() {
		try {
			org.apache.directory.api.ldap.model.entry.Entry entry = new DefaultEntry("ou=tenants,o=emc", ORGOBJCLS,
					TENANCYOBJCLS, TOPOBJCLS, "ou:tenants");
			getEmbedPool().getConnection().add(entry);
		} catch (LdapException e) {
			logger.debug("LdapException : " + e);
		}
	}

	/**
	 * @param configuration
	 * @throws Exception
	 */
	protected void useTLS(AppConfig configuration) throws Exception {
		ldapServer.setKeystoreFile(configuration.getCertName());
		ldapServer.setCertificatePassword(configuration.getCertPwd());
		ldapServer.addExtendedOperationHandler(new StartTlsHandler());
	}

	/**
	 * @param directoryServiceFactory
	 * @throws Exception
	 */
	protected void setSession(DirectoryServiceFactory directoryServiceFactory) throws Exception {
		directoryServiceFactory.init(DIRNAME);
		service = directoryServiceFactory.getDirectoryService();
		if (service != null) {
			getSessionFromService();
		}
	}

	/**
	 * @throws Exception
	 */
	protected void getSessionFromService() {
		try {
			dsSession = service.getSession();
		} catch (Exception e) {
			logger.info("getsession from service exception: " + e);
		}
		setDsSession(dsSession);
	}

	
	/**
	 * @param connectors
	 * @param connectorName
	 * @param connectorConfig
	 * @throws LdapException
	 */
	protected ProxyConnector bootstrapConnections(Map<String, ProxyConnector> connectors, String connectorName,
			ConnectorInfo connectorInfo) throws LdapException {
		ProxyConnector connector;
		connector = getDefaultProxyConnector(connectorInfo);
		connectors.put(connectorName, connector);
		return connector;
	}

	/**
	 * @param connectorConfig
	 * @return
	 * @throws LdapException
	 */
	protected ProxyConnector getDefaultProxyConnector(ConnectorInfo connectorInfo) throws LdapException {
		ProxyConnector connector = null;
		if (connector == null) {
			connector = new DefaultProxyConnector(connectorInfo);
		}
		return connector;
	}

	/**
	 * @param config
	 * @return
	 */
	protected RolodexVault getRolodexVault(AppConfig config) {
		RolodexVault vault = new RolodexVault();
		vault.setUrl(config.getVaultUrl());
		vault.setToken(config.getVaultToken());
		vault.setContextPath(config.getRemoteContextPath());
		return vault;
	}

	/**
	 * @param connectors
	 */
	public void addConnectors(Map<String, ProxyConnector> connectors) {
		this.connectors = connectors;
	}

	/**
	 * @param config
	 * @throws LdapException
	 * @throws IOException
	 */
	protected void restoreCustomLDif(AppConfig config) throws LdapException, IOException {

		if (inputStream == null) {
			inputStream = getInputStream(config);
		}
		LdifReader entries = null;
		try {
			entries = new LdifReader(inputStream);
			loopLdifEntries(entries);
		} catch (LdapException e) {
			logger.info(e.getMessage());
		}
	}

	/**
	 * @param entries
	 * @throws LdapException
	 * @throws IOException
	 */
	protected void loopLdifEntries(LdifReader entries) throws LdapException, IOException {
		LdapConnection connection = null;
		for (LdifEntry ldifEntry : entries) {
			org.apache.directory.api.ldap.model.entry.Entry entry = ldifEntry.getEntry();
			AddRequest addRequest = new AddRequestImpl();
			addRequest.setEntry(entry);
			connection = getEmbedPool().getConnection();
			connection.add(addRequest);
		}
		getEmbedPool().releaseConnection(connection);
	}

	/**
	 * @param config
	 * @return
	 */
	protected InputStream getInputStream(AppConfig config) {
		inputStream = ClassLoader.getSystemClassLoader().getResourceAsStream(config.getSchemaFileName());
		return inputStream;
	}

	/**
	 * @param config
	 * @return
	 */
	protected boolean createEmbeddedConnection(AppConfig config) {
		embeddedConnector = new EmbeddedConnector();
		if (embeddedConnector.connect(config.getHostName(), config.getPort(), config.getLocalUserName(),
				config.getLocalPasswd(), config, true)) {
			setEmbedPool(embeddedConnector.getPool());
			setEmbeddedConnector(embeddedConnector);
			return true;
		}
		return false;
	}

	/**
	 * @param cursor
	 * @throws CursorException
	 */
	protected void iterateCursor(EntryCursor cursor) throws CursorException {
		org.apache.directory.api.ldap.model.entry.Entry entry = cursor.get();
		nodes.add(entry);
	}

	/**
	 * @param config
	 * @return
	 */
	protected org.apache.directory.api.ldap.model.entry.Entry initPartition(AppConfig config) {
		org.apache.directory.api.ldap.model.entry.Entry contextEntry = null;
		try {
			String[] partitionPart = config.getPartitionName().split("=");
			String partition = partitionPart[0] + ":" + partitionPart[1];
			contextEntry = new DefaultEntry(config.getPartitionName(), ORGANIZATIONOBJ, TOPOBJ, partition);
			getEmbedPool().getConnection().add(contextEntry);
		} catch (LdapException e) {
			logger.debug("LdapException: " + e);
		}
		return contextEntry;
	}

	/**
	 * @return
	 */
	public Map<String, ProxyConnector> getConnectors() {
		return connectors;
	}

	/**
	 * @param connectors
	 */
	public void setConnectors(Map<String, ProxyConnector> connectors) {
		this.connectors = connectors;
	}

	/**
	 * @return
	 */
	public ProxyInterceptor getProxyInterceptor() {
		return proxyInterceptor;
	}

	/**
	 * @return
	 */
	public Map<String, ProxyConfiguration> getHandlers() {
		return handlers;
	}

	/**
	 * @param handlers
	 */
	public void setHandlers(Map<String, ProxyConfiguration> handlers) {
		this.handlers = handlers;
	}

	/**
	 * @param nodes
	 */
	public void setNodes(List<org.apache.directory.api.ldap.model.entry.Entry> nodes) {
		this.nodes = nodes;
	}

	/**
	 * @return
	 */
	public List<org.apache.directory.api.ldap.model.entry.Entry> getNodes() {
		return nodes;
	}

	/**
	 * @return
	 */
	public String getConnectorName() {
		return connectorName;
	}

	/**
	 * @param connectorName
	 */
	public void setConnectorName(String connectorName) {
		this.connectorName = connectorName;
	}

	/**
	 * @return
	 */
	public ProxyConnector getConnector() {
		return connector;
	}

	/**
	 * @param connector
	 */
	public void setConnector(ProxyConnector connector) {
		this.connector = connector;
	}

	/**
	 * get core session object
	 * 
	 * @return
	 */
	public CoreSession getDsSession() {
		return dsSession;
	}

	/**
	 * set core session object
	 * 
	 * @param dsSession
	 */
	public void setDsSession(final CoreSession dsSession) {
		this.dsSession = dsSession;
	}

	/**
	 * @return
	 */
	public DirectoryService getService() {
		return service;
	}

	/**
	 * @param service
	 */
	public void setService(DirectoryService service) {
		this.service = service;
	}

	/**
	 * @return LdapServer
	 */
	public LdapServer getLdapServer() {
		return ldapServer;
	}

	/**
	 * @param ldapServer
	 */
	public void setLdapServer(LdapServer ldapServer) {
		this.ldapServer = ldapServer;
	}

	/**
	 * @return LdapNetworkConnection
	 */
	public LdapConnectionPool getEmbedPool() {
		return pool;
	}

	/**
	 * @param embedConnection
	 */
	public void setEmbedPool(LdapConnectionPool pool) {
		this.pool = pool;
	}

	/**
	 * @return InputStream
	 */
	public InputStream getInputStream() {
		return inputStream;
	}

	/**
	 * @param inputStream
	 */
	public void setInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
	}

	/**
	 * @return
	 */
	public EmbeddedConnector getEmbeddedConnector() {
		return embeddedConnector;
	}

	/**
	 * @param embeddedConnector
	 */
	public void setEmbeddedConnector(EmbeddedConnector embeddedConnector) {
		this.embeddedConnector = embeddedConnector;
	}

	/**
	 * @param ctr
	 * @return
	 */
	public String getHostNameOrIP(String ctr) {
		String[] ctrParams = ctr.split(":");
		return ctrParams[0];
	}
	
	/**
	 * @param ctr
	 * @return
	 */
	public String getPort(String ctr) {
		String[] ctrParams = ctr.split(":");
		return ctrParams[1];
	}
	

	/**
	 * @param host
	 * @return
	 */
	public ProxyConnector getConnectorByHost(String host) {
		if (getConnectors().containsKey(host)) {
			return getConnectors().get(host);
		}
		return null;
	}

	/**
	 * @param connectors
	 * @param connectorName
	 * @param connectorConfig
	 * @throws LdapException
	 */
	public void bootstrapConnectionsNew(Map<String, ProxyConnector> connectors, String connectorName,
			ConnectorInfo connectorInfo) throws LdapException {
		ProxyConnector connector = new DefaultProxyConnector(connectorInfo);
		connectors.put(connectorName, connector);
	}

	/**
	 * @param connectors
	 * @param connectorName
	 * @param connectorConfig
	 * @throws LdapException
	 */
	public ProxyConnector bootstrapConnectionsForTenant(ConnectorInfo connectorInfo) throws LdapException {
		return new DefaultProxyConnector(connectorInfo);
	}

	/**
	 * @return
	 */
	public TenancyInterceptor getTenancyInterceptor() {
		return tenancyInterceptor;
	}

	/**
	 * @param tenancyInterceptor
	 */
	public void setTenancyInterceptor(TenancyInterceptor tenancyInterceptor) {
		this.tenancyInterceptor = tenancyInterceptor;
	}

	/**
	 * @param tenantAdd
	 */
	public void addTenantsRunTime(String tenant, org.apache.directory.api.ldap.model.entry.Entry tenantAdd) {
		tenants.put(tenant, tenantAdd);
	}

	/**
	 * @return
	 */
	public ConcurrentHashMap<String,org.apache.directory.api.ldap.model.entry.Entry> getAllTenants() {
		return tenants;
	}

	/**
	 * @return
	 */
	public AppConfig getConfig() {
		return config;
	}

	/**
	 * @param config
	 */
	public void setConfig(AppConfig config) {
		this.config = config;
	}

	/**
	 * @param isFullyLoaded
	 */
	public void setIsFullyStarted(boolean isFullyLoaded) {
		this.isFullyLoaded = isFullyLoaded;
	}

	/**
	 * @return boolean
	 */
	public boolean isFullyLoaded() {
		return isFullyLoaded;
	}
	
	public ConnectorInfo getDefaultConnector() {
		return defaultConnector;
	}

	public void setDefaultConnector(ConnectorInfo defaultConnector) {
		this.defaultConnector = defaultConnector;
	}

}