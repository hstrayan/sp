package com.pers.smartproxy;
//package com.virtustream.coreservices.rolodex;
//
//import static org.junit.Assert.assertEquals;
//import static org.junit.Assert.assertNotNull;
//import static org.junit.Assert.assertTrue;
//
//import java.util.HashMap;
//import java.util.Map;
//
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.junit.Before;
//import org.junit.Test;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//
//import com.virtustream.coreservices.rolodex.representations.ProxyConfiguration;
//
//public class AppConfigTest {
//	
//	private AppConfig appConfig;
//	private static final String HOSTNAME = "localHost";
//	private static final int PORT = 11389;
//	private static final String SERVERADDR = "serverAddress";
//	private static final String USERNAME = "localUserName";
//	private static final String PWD = "localPasswd";
//	private static final String PARTNAME = "partitionName";
//	private static final String INTR = "interceptor";
//	private static final String PARTLOC = "partitionLoc";
//	private static final String PARENTNODE = "parentNode";
//	private static final String SCHEMAFILE = "rolodex.ldif";
//	private static final String CONNECTOR = "connector";
//	private static final String SERVICENAME = "serviceName";
//	private static final int NBTHREADS = 100;
//	private static final int BACKLOG = 1;
//	private static final boolean TP = true;
//	private static final boolean CUSTOMPARTITION =true;
//	private  static final boolean CHANGELOG = true;
//	@Mock
//	private Map<String, ProxyConfiguration> proxyDefinitions;
//	@Mock
//	private Map<String, Map<String, String>> defaultConnectorConfiguration;
//	@Mock
//	private Map<String, Map<String, String>> defaultConnectorOperations;
//	@Mock
//	private Map<String, Map<String, String>> failOverConnectorConfiguration;
//
//
//	@Before
//	public void init() throws LdapException {
//		MockitoAnnotations.initMocks(this);
//		appConfig = new AppConfig();
//		appConfig.setHostName(HOSTNAME);
//		appConfig.setPort(PORT);
//		appConfig.setServerAddress(SERVERADDR);
//		appConfig.setLocalUserName(USERNAME);
//		appConfig.setLocalPasswd(PWD);
//		appConfig.setPartitionName(PARTNAME);
//		appConfig.setInterceptor(INTR);
//		appConfig.setPartitionLoc(PARTLOC);
//		appConfig.setParentNode(PARENTNODE);
//		appConfig.setSchemaFileName(SCHEMAFILE);
//		appConfig.setConnector(CONNECTOR);
//		appConfig.setServiceName(SERVICENAME);
//		appConfig.setNbThreads(NBTHREADS);
//		appConfig.setBacklog(BACKLOG);
//		appConfig.setTransparentProxy(TP);
//		appConfig.setUseCustomPartition(true);
//		appConfig.setChangeLog(true);
//	//	appConfig.setProxyDefinitions(proxyDefinitions);
//		appConfig.setDefaultConnectorConfiguration(defaultConnectorConfiguration);
//		appConfig.setDefaultConnectorOperations(defaultConnectorOperations);
//		appConfig.SetFailOverConnectorConfiguration(failOverConnectorConfiguration);
//		String[] indexAttrs = {"o,ou"};
//		appConfig.setIndexAttrs(indexAttrs);
//		String[] connectors = {"ctr1","ctr2"};
//		appConfig.setConnectors(connectors);
//		appConfig.setCachedEntries(5);
//		appConfig.setSchemaFilter("filter");
//		Map<String,ProxyConfiguration> tenants = new HashMap<String,ProxyConfiguration> ();
//		appConfig.setTenantMappingReqs(tenants);
//		 Map<String, String[]>  srcAttrs = new HashMap<String, String[]>();
//	//	 appConfig.setSourceAttributes(srcAttrs);
//		 appConfig.setVaultUrl("test url");
//		 appConfig.setVaultToken("root token");
//		 appConfig.setLocalContextPath("/usr/bin");
//		 appConfig.setRemoteContextPath("/remote/bin");
//		 appConfig.setUseTls(true);
//		 appConfig.setTenancyDn("ou=tenants");
//		 appConfig.setCertName("certName");
//		 appConfig.setCertPwd("certPwd");
//		 appConfig.setUseVault(true);
//		 appConfig.setSSL(true);
//		 appConfig.setSslPort(636);
//	}
//	
//	@Test
//	public void testInvocations() {
//		AppConfig spy = Mockito.spy(appConfig);
//		assertNotNull(spy.getHostName());
//		assertEquals(spy.getHostName(), HOSTNAME);
//		assertNotNull(spy.getPort());
//		assertEquals(spy.getPort(), PORT);
//		assertNotNull(spy.getServerAddress());
//		assertEquals(spy.getServerAddress(), SERVERADDR);
//		assertNotNull(spy.getLocalUserName());
//		assertEquals(spy.getLocalUserName(), USERNAME);
//		assertNotNull(spy.getLocalPasswd());
//		assertEquals(spy.getLocalPasswd(), PWD);
//		assertNotNull(spy.getPartitionName());
//		assertEquals(spy.getPartitionName(), PARTNAME);
//		assertNotNull(spy.getInterceptor());
//		assertEquals(spy.getInterceptor(), INTR);
//		assertNotNull(spy.getPartitionLoc());
//		assertEquals(spy.getPartitionLoc(), PARTLOC);
//		assertNotNull(spy.getParentNode());
//		assertEquals(spy.getParentNode(), PARENTNODE);
//		assertNotNull(spy.getSchemaFileName());
//		assertEquals(spy.getSchemaFileName(), SCHEMAFILE);
//		assertNotNull(spy.getConnector());
//		assertEquals(spy.getConnector(), CONNECTOR);
//		assertNotNull(spy.getServiceName());
//		assertEquals(spy.getServiceName(), SERVICENAME);
//		assertNotNull(spy.getNbThreads());
//		assertEquals(spy.getNbThreads(), NBTHREADS);
//		assertNotNull(spy.getBacklog());
//		assertEquals(spy.getBacklog(), BACKLOG);
//		assertNotNull(spy.isTransparentProxy());
//		assertEquals(spy.isTransparentProxy(), TP);
//		assertNotNull(spy.isUseCustomPartition());
//		assertEquals(spy.isUseCustomPartition(), CUSTOMPARTITION);
//		assertNotNull(spy.isChangeLog());
//		assertEquals(spy.isChangeLog(), CHANGELOG);
//	//	assertNotNull(spy.getProxyDefinitions());
//		assertNotNull(spy.getDefaultConnectorConfiguration());
//		assertNotNull(spy.getDefaultConnectorOperations());
//		assertNotNull(spy.getFailOverConnectorConfiguration());
//		assertNotNull(spy.getIndexAttrs());
//		assertNotNull(spy.getConnectors());
//		assertEquals(spy.getCachedEntries(),5);
//		assertNotNull(spy.getSchemaFilter());
//		assertNotNull(spy.getTenantMappingReqs());
//	//	assertNotNull(spy.getSourceAttributes());
//		assertNotNull(spy.getVaultUrl());
//		assertNotNull(spy.getVaultToken());
//		assertNotNull(spy.getLocalContextPath());
//		assertNotNull(spy.getRemoteContextPath());
//		assertTrue(spy.isUseTls());
//		assertNotNull(spy.getTenancyDn());
//		assertNotNull(spy.getCertName());
//		assertNotNull(spy.getCertPwd());
//		assertTrue(spy.isUseVault());
//		assertTrue(spy.isSSL());
//		assertNotNull(spy.getSslPort());
//	}
//}
