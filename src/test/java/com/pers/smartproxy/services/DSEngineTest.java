package com.pers.smartproxy.services;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.factory.DefaultDirectoryServiceFactory;
import org.apache.directory.server.core.factory.DirectoryServiceFactory;
import org.apache.directory.server.core.normalization.NormalizationInterceptor;
import org.apache.directory.server.ldap.LdapServer;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.connectors.DefaultProxyConnector;
import com.pers.smartproxy.connectors.EmbeddedConnector;
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.handlers.ConditionHandler;
import com.pers.smartproxy.handlers.MappingConditionHandler;
import com.pers.smartproxy.interceptors.ProxyInterceptor;
import com.pers.smartproxy.representations.Endpoint;
import com.pers.smartproxy.representations.ProxyConfiguration;
import com.pers.smartproxy.representations.RolodexVault;
import com.pers.smartproxy.AppConfig;

public class DSEngineTest {

	DSEngine dSEngine;
	@Mock
	DirectoryService directoryService;
	@Mock
	AppConfig config;
	@Mock
	AppConfig config2;
	@Mock
	ProxyInterceptor intr;
	@Mock
	NormalizationInterceptor nIntr;
	@Mock
	ProxyConnector connector;
	@Mock
	Map<String, ProxyConnector> connectors;
	@Mock
	List<Interceptor> intrs;
	@Mock
	Entry node;
	@Mock
	SchemaManager schemaManager;
	@Mock
	Map<String, Endpoint> machines;
	// @Mock
	DirectoryServiceFactory factory = new DefaultDirectoryServiceFactory();
	@Mock
	CoreSession session;
	@Mock
	Map<String, String> connectorConfig;
	@Mock
	LdapNetworkConnection embedded;
	@Mock
	Map<String, ProxyConnector> ctrs;
	@Mock
	Map<String, Map<String, String>> defaultConnectorConfiguration;
	@Mock
	InputStream inputStream;
	@Mock
	LdifReader entries;
	@Mock
	Map<String, ProxyConfiguration> handlers;
	@Mock
	LdapServer ldapServer;
	@Mock
	EntryCursor entryCursor;
	@Mock
	LdapConnectionPool pool;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testDSEngineMethods() throws Exception {
		DSEngine dsEngine = new DSEngine();

		dsEngine.setConnector(connector);
		assertNotNull(dsEngine.getConnector());
		dsEngine.setConnectorName("ldapConnector");
		assertNotNull(dsEngine.getConnectorName());

		dsEngine.addConnectors(connectors);
		assertNotNull(dsEngine.getConnectors());
		List<Entry> nodes = new ArrayList<Entry>();
		nodes.add(node);
		assertNotNull(dsEngine.getNodes());
		directoryService.setSchemaManager(schemaManager);

		DSEngine spy = Mockito.spy(dsEngine);
		String[] connectorsArray = { "test1", "test2" };
	

		List<Entry> nodelist = new ArrayList<Entry>();
		Entry entry = new DefaultEntry();
		entry.setDn(new Dn("o=emc"));
		nodes.add(entry);
	

		Mockito.doCallRealMethod().when(spy).setConnectors(connectors);
		assertNotNull(spy.getConnectors());
		Mockito.doCallRealMethod().when(spy).setConnector(connector);
		assertNotNull(spy.getConnector());

	}

	@Test
	public void testSetSession() {
		try {
			DSEngine dsEngine = new DSEngine();
			DirectoryServiceFactory factory = Mockito.mock(DirectoryServiceFactory.class);
			dsEngine.setSession(factory);
			DirectoryService service = Mockito.mock(DirectoryService.class);
			dsEngine.setService(service);
			dsEngine.getSessionFromService();
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testUseTLS() {
		try {
			DSEngine dsEngine = new DSEngine();
			LdapServer ldapServer = Mockito.mock(LdapServer.class);
			dsEngine.setLdapServer(ldapServer);
			AppConfig config = new AppConfig();
			config.setCertName("test cert");
			config.setCertPwd("cert pwd");
			DSEngine spy = Mockito.spy(dsEngine);
			Mockito.doCallRealMethod().when(spy).useTLS(config);
			dsEngine.useTLS(config);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testAddNodes() {
		try {
			DSEngine dsEngine = new DSEngine();
			Entry entry = Mockito.mock(Entry.class);
			entry.setDn(new Dn("o=testdn"));
			Map<String, ProxyConnector> connectors = new HashMap<String, ProxyConnector>();
			ConditionHandler handler = Mockito.mock(ConditionHandler.class);
			ProxyConnector connector = new DefaultProxyConnector();
			connector.addHandler(handler);
			connectors.put("ctr1", connector);
			dsEngine.setConnectors(connectors);
		
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testAddHandlers() throws LdapException {

		Map.Entry<String, ProxyConnector> server = new Map.Entry<String, ProxyConnector>() {

			@Override
			public String getKey() {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public ProxyConnector getValue() {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public ProxyConnector setValue(ProxyConnector value) {
				// TODO Auto-generated method stub
				return null;
			}
		};
		MappingConditionHandler conditionHandler = new MappingConditionHandler();

		try {
			DSEngine dsEngine = new DSEngine();
			ArrayList<org.apache.directory.api.ldap.model.entry.Entry> nodes = new ArrayList<Entry>();
			Entry entry = new DefaultEntry();
			entry.setDn(new Dn("o=testDn"));
			Attribute attr1 = new DefaultAttribute("serverName");
			attr1.add("test");
			Attribute attr2 = new DefaultAttribute("endpoint");
			attr2.add("test2");
			entry.add(attr1);
			entry.add(attr2);
			nodes.add(entry);
			dsEngine.setNodes(nodes);
			ProxyConnector value = new DefaultProxyConnector();
			conditionHandler.setNodes(nodes);
			value.addHandler(conditionHandler);
			server.setValue(value);

			} catch (Exception e) {
		}
	}

	@Test
	public void testRolodexVaultAssignment() throws Exception {
		DSEngine dsEngine = new DSEngine();
		AppConfig config = Mockito.mock(AppConfig.class);
		config.setVaultUrl("url");
		config.setVaultToken("token");
		config.setRemoteContextPath("/path");
		RolodexVault vault = dsEngine.getRolodexVault(config);
		assertNotNull(vault);
	}

	@Test
	public void testBootstrapConnections() throws Exception {
		Map<String, ProxyConnector> map = new HashMap<String, ProxyConnector>();
		String connectorName = "testconnector";
		DSEngine dsEngine = new DSEngine();
		DSEngine spy = Mockito.spy(dsEngine);
	//	Mockito.doNothing().when(spy).bootstrapConnectionsNew(map, connectorName, connectorConfig);
	}

//	@Test
//	public void testEmbeddedConnection() {
//		try {
//			DSEngine dsEngine = new DSEngine();
//			AppConfig config = new AppConfig();
//			config.setHostName("localhost");
//			config.setPort(389);
//			config.setLocalUserName("test user");
//			config.setLocalPasswd("local pwd");
//			LdapNetworkConnection connection = dsEngine.getEmbeddedConnection(config);
//		} catch (Exception e) {
//			assertNotNull(e);
//		}
//
//	}

	

	@Test
	public void testAddCustomPartition() {
		try {
			DSEngine dsEngine = new DSEngine();
			Entry contextEntry = new DefaultEntry();
			contextEntry.setDn("o=testDn");
			String partition = "o=emc";
			String mappingOu = "ou=mapping";
			LdapNetworkConnection connection = Mockito.mock(LdapNetworkConnection.class);
		//	dsEngine.addCustomPartition(contextEntry, partition, mappingOu);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testLoopLdifs() throws LdapException, IOException {
		AppConfig config = new AppConfig();
		DSEngine dsEngine = new DSEngine();
		EmbeddedConnector connector = new EmbeddedConnector();
		connector.setPool(pool);
		dsEngine.setEmbeddedConnector(connector);
		dsEngine.setEmbedPool(pool);
		LdifReader reader = new LdifReader();
		reader.parseLdif("dn: dc=example,dc=com");
		dsEngine.loopLdifEntries(reader);
	}

	@Test
	public void testMiscMethods() throws LdapException {
		DSEngine dsEngine = new DSEngine();
		dsEngine.setHandlers(handlers);
		assertNotNull(dsEngine.getHandlers());
		dsEngine.setEmbedPool(pool);
		assertNotNull(dsEngine.getEmbedPool());
		dsEngine.setInputStream(inputStream);
		assertNotNull(dsEngine.getInputStream());
		dsEngine.setLdapServer(ldapServer);
		assertNotNull(dsEngine.getLdapServer());
	}

	@Test
	public void testIterateCursor() throws LdapException, CursorException {
		DSEngine dsEngine = new DSEngine();
		ArrayList<org.apache.directory.api.ldap.model.entry.Entry> nodes = new ArrayList<Entry>();
		dsEngine.setNodes(nodes);
		Entry entry = new DefaultEntry();
		EntryCursor cursor = Mockito.mock(EntryCursor.class);
		// cursor.after(entry);
		dsEngine.iterateCursor(cursor);

	}

	
	@Test
	public void testLoadParentNodes() {
		try {
			DSEngine dsEngine = new DSEngine();
			embedded.isConnected();
			dsEngine.setEmbedPool(pool);

			AppConfig config = new AppConfig();
			config.setPartitionName("o=emc");
		//	dsEngine.loadParentNodes(config);
		} catch (Exception e) {
		}

	}

	@Test
	public void testLoopConnectors() {
		DSEngine dsEngine = new DSEngine();
		Map<String, ProxyConnector> ctr = new HashMap<String, ProxyConnector>();
		ctr.put("ctr1", new DefaultProxyConnector());
		dsEngine.setConnectors(ctr);
	//	dsEngine.loopConnectors();

	}

	@Test
	public void testInsertInterceptor() {
		DSEngine dsEngine = new DSEngine();
		AppConfig config = new AppConfig();

		config.setDefaultConnectorConfiguration(defaultConnectorConfiguration);
		//dsEngine.insertInterceptor(config);

	}



}