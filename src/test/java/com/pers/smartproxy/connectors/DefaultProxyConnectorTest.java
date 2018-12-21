package com.pers.smartproxy.connectors;
//package com.virtustream.coreservices.rolodex.connectors;
//
//import static org.junit.Assert.assertNotNull;
//import static org.junit.Assert.assertNull;
//
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//
//import org.apache.commons.pool.PoolableObjectFactory;
//import org.apache.directory.api.ldap.model.cursor.CursorException;
//import org.apache.directory.api.ldap.model.cursor.EntryCursor;
//import org.apache.directory.api.ldap.model.entry.DefaultEntry;
//import org.apache.directory.api.ldap.model.entry.DefaultModification;
//import org.apache.directory.api.ldap.model.entry.Entry;
//import org.apache.directory.api.ldap.model.entry.Modification;
//import org.apache.directory.api.ldap.model.entry.ModificationOperation;
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.apache.directory.api.ldap.model.message.ModifyRequest;
//import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
//import org.apache.directory.api.ldap.model.message.SearchRequest;
//import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
//import org.apache.directory.api.ldap.model.message.SearchScope;
//import org.apache.directory.api.ldap.model.name.Dn;
//import org.apache.directory.ldap.client.api.LdapConnection;
//import org.apache.directory.ldap.client.api.LdapConnectionPool;
//import org.apache.directory.server.core.api.CoreSession;
//import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
//import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
//import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
//import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
//import org.junit.Before;
//import org.junit.Test;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//
//import com.virtustream.coreservices.rolodex.handlers.ConditionHandler;
//import com.virtustream.coreservices.rolodex.handlers.MappingConditionHandler;
//import com.virtustream.coreservices.rolodex.operations.AddOperation;
//import com.virtustream.coreservices.rolodex.operations.DeleteOperation;
//import com.virtustream.coreservices.rolodex.utils.ConnectionManager;
//
//public class DefaultProxyConnectorTest {
//
//	@Mock
//	Entry entry;
//
//	@Mock
//	List<Entry> entries;
//	@Mock
//	CoreSession session;
//
//	SearchOperationContext searchContext = new SearchOperationContext(session);
//	//
//	AddOperationContext addContext = new AddOperationContext(null);
//
//	DeleteOperationContext deleteContext = new DeleteOperationContext(null);
//
//	ModifyOperationContext modifyContext = new ModifyOperationContext(null);
//
//	@Mock
//	LdapConnectionPool pool;
//
//	ConnectionManager cnManager;
//
//	@Mock
//	EntryCursor cursor;
//
//	@Mock
//	List<EntryCursor> cursors;
//
//	// @Mock
//	List<Dn> dns = new ArrayList<Dn>();
//	// @Mock
//	List<Modification> updatedMods = new ArrayList<Modification>();
//	@Mock
//	ModifyRequest modifyRequest;
//	@Mock
//	LdapConnection connection;
//	@Mock
//	PoolableObjectFactory factory;
//
//	@Mock
//	MappingConditionHandler handler;
//
//	Map<String, String> connectorConfig;
//
//	private DefaultProxyConnector defaultConnector;
//
//	@Before
//	public void init() throws LdapException {
//		MockitoAnnotations.initMocks(this);
//		connectorConfig = new HashMap<String, String>();
//		connectorConfig.put("useTLS", "false");
//		connectorConfig.put("hostname", "hostname");
//		connectorConfig.put("port", "11389");
//		connectorConfig.put("username", "username");
//		connectorConfig.put("pwd", "pwd");
//
//		defaultConnector = new DefaultProxyConnector();
//	//	defaultConnector.setConnManager(new ConnectionManager(connectorConfig));
//	}
//
//	@SuppressWarnings("deprecation")
//	@Test
//	public void testSupportMethods() throws Exception {
//
//		SearchRequest searchRequest = new SearchRequestImpl();
//		searchRequest.setBase(new Dn("o=vsc"));
//		searchRequest.setScope(SearchScope.SUBTREE);
//		searchRequest.setFilter("(objectClass=*)");
//		searchRequest.addAttributes("*");
//
//		searchContext = new SearchOperationContext(null, searchRequest);
//		defaultConnector.modify(connection, modifyRequest);
//
//		defaultConnector.setPool(pool);
//
//		defaultConnector.addHandler(handler);
//
//		Mockito.when(defaultConnector.getUpdatedEntry(entry)).thenReturn(entries);
//		assertNotNull(defaultConnector.getUpdatedEntry(entry));
//
//		Mockito.when(defaultConnector.getUpdatedDn(new Dn("o=vsc"))).thenReturn(dns);
//		assertNotNull(defaultConnector.getUpdatedDn(new Dn("o=vsc")));
//
//		DefaultProxyConnector mocks = Mockito.mock(DefaultProxyConnector.class);
//		DefaultProxyConnector spy = Mockito.spy(mocks);
//
//		Mockito.doCallRealMethod().when(spy).propagateModify(dns, updatedMods, connection);
//		Dn dn = new Dn("o=emc");
//		dns.add(dn);
//		Modification mod = new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "attr1", "attr2");
//		updatedMods.add(mod);
//		spy.propagateModify(dns, updatedMods, connection);
//
//		Mockito.doCallRealMethod().when(spy).performModify(dn, updatedMods, connection);
//		spy.performModify(dn, updatedMods, connection);
//
//		defaultConnector.addHandler(handler);
//		Mockito.when(defaultConnector.getUpdatedMods(dn, updatedMods)).thenReturn(updatedMods);
//		defaultConnector.getUpdatedMods(dn, updatedMods);
//		pool.setFactory(factory);
//		spy.setPool(pool);
//		addContext.setEntry(new DefaultEntry());
//		Mockito.doNothing().when(spy).add(addContext, false);
//		// defaultConnector.add(addContext, false);
//
//		Mockito.doNothing().when(spy).delete(deleteContext, false);
//		// defaultConnector.delete(deleteContext, false);
//
//		Mockito.doNothing().when(spy).modify(modifyContext, false);
//		// defaultConnector.modify(modifyContext, false);
//		String[] attrs = { "cn", "sn" };
//		assertNotNull(defaultConnector.searchMappedDns(dn, attrs));
//
//	}
//
//	@Test
//	public void testAdd() throws LdapException {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		Entry entry = Mockito.mock(Entry.class);
//		connector.setPool(pool);
//		Mockito.spy(connector).add(entry, true);
//
//	}
//
//	@Test
//	public void testAddMultipleEntries() {
//		try {
//			DefaultProxyConnector connector = new DefaultProxyConnector();
//			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//			Entry entry = Mockito.mock(Entry.class);
//			connector.setPool(pool);
//			List<Entry> entries = new ArrayList<Entry>();
//			entries.add(entry);
//			LdapConnection connection = Mockito.mock(LdapConnection.class);
//			AddOperation add = new AddOperation();
//			Mockito.spy(connector).addMultipleEntries(entries, connection, add);
//		} catch (Exception e) {
//			assertNull(e);
//		}
//	}
//
//	@Test
//	public void testDeleteMultipleEntries() {
//		try {
//			DefaultProxyConnector connector = new DefaultProxyConnector();
//			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//			List<Dn> dns = new ArrayList<Dn>();
//			dns.add(new Dn("o=test"));
//			connector.setPool(pool);
//			List<Entry> entries = new ArrayList<Entry>();
//			entries.add(entry);
//			LdapConnection connection = Mockito.mock(LdapConnection.class);
//			DeleteOperation delete = new DeleteOperation();
//			Mockito.spy(connector).performMultipleDeletes(dns, connection, delete);
//		} catch (Exception e) {
//			assertNull(e);
//		}
//	}
//
//	@Test
//	public void testModifyNonMapping() throws LdapException {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		ModifyRequest modifyRequest = new ModifyRequestImpl();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		Entry entry = Mockito.mock(Entry.class);
//		connector.setPool(pool);
//		modifyContext.setDn(new Dn("o=testdn"));
//		Mockito.spy(connector).modify(modifyRequest);
//	}
//
//	@Test
//	public void testModifyPropagate() throws Exception {
//		try {
//			DefaultProxyConnector connector = new DefaultProxyConnector();
//			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//			List<Dn> dns = new ArrayList<Dn>();
//			dns.add(new Dn("o=test"));
//			connector.setPool(pool);
//			List<Modification> updatedMods = new ArrayList<Modification>();
//			Modification addedGivenName = new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "givenName",
//					"John", "Peter");
//			updatedMods.add(addedGivenName);
//			LdapConnection connection = Mockito.mock(LdapConnection.class);
//			ModifyRequest modifyRequest = new ModifyRequestImpl();
//			modifyContext.setDn(new Dn("o=testdn"));
//			modifyRequest.addModification(addedGivenName);
//			ConditionHandler handler = Mockito.mock(ConditionHandler.class);
//			connector.addHandler(handler);
//			Mockito.spy(connector).updateAndPropagateModify(modifyRequest, dns, connection);
//		} catch (Exception e) {
//			assertNull(e);
//		}
//	}
//
//	@Test
//	public void testModifyMapping() throws LdapException {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		modifyContext.setDn(new Dn("o=testDn"));
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		Entry entry = Mockito.mock(Entry.class);
//		connector.setPool(pool);
//		modifyContext.setDn(new Dn("o=testdn"));
//		Mockito.spy(connector).modify(modifyContext, true);
//
//	}
//
//	// @Test
//	// public void testAddOperationContext() throws LdapException {
//	// DefaultProxyConnector connector = new DefaultProxyConnector();
//	// LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//	// connector.setPool(pool);
//	// Entry entry = Mockito.mock(Entry.class);
//	// addContext.setEntry(entry);
//	// Mockito.spy(connector).add(addContext, true);
//	//
//	// }
//
//	@Test
//	public void testAddOperationContextNotTransparent() throws LdapException {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		connector.setPool(pool);
//		Entry entry = Mockito.mock(Entry.class);
//		addContext.setEntry(entry);
//		Mockito.spy(connector).add(addContext, false);
//
//	}
//
//	@Test
//	public void testIterateEntriesAndAdd() throws LdapException {
//		List<Entry> entries = new ArrayList<Entry>();
//		AddOperation add = Mockito.mock(AddOperation.class);
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		connector.setPool(pool);
//		Entry entry = Mockito.mock(Entry.class);
//		entries.add(entry);
//		Mockito.spy(connector).iterateEntriesAndAdd(entries, connection, add);
//	}
//
//	@Test
//	public void testSearchAndLoadCursor() throws Exception {
//		Dn dn = new Dn("o=testDn");
//		String[] attrs = { "testattr1", "testattr2" };
//		List<Dn> dns = new ArrayList<Dn>();
//		dns.add(new Dn("o=newDn"));
//		List<EntryCursor> cursors = new ArrayList<EntryCursor>();
//
//		LdapConnection connection = Mockito.mock(LdapConnection.class);
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		ConditionHandler handler = Mockito.mock(ConditionHandler.class);
//		connector.addHandler(handler);
//		Mockito.spy(connector).searchAndLoadCursor(dn, attrs, dns, connection, cursors);
//	}
//
//	@Test
//	public void testSearchByDn() throws LdapException, CursorException {
//		searchContext.setDn(new Dn("o=testDn"));
//		searchContext.setReturningAttributes("*");
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		LdapConnection connection = Mockito.mock(LdapConnection.class);
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		connector.setPool(pool);
//		Mockito.spy(connector).searchByDn(searchContext);
//	}
//
//	@Test
//	public void testcascadeDelete() throws LdapException {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		Entry entry = Mockito.mock(Entry.class);
//		connector.setPool(pool);
//		Mockito.spy(connector).cascadeDelete(new Dn("ou=testDn,o=emc"));
//	}
//
//	@Test
//	public void testDelete() throws LdapException {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		Entry entry = Mockito.mock(Entry.class);
//		connector.setPool(pool);
//		Mockito.spy(connector).delete(new Dn("ou=testDn,o=emc"));
//	}
//
//	@Test
//	public void testauthenticate() {
//		try {
//			DefaultProxyConnector connector = new DefaultProxyConnector();
//			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//			Entry entry = Mockito.mock(Entry.class);
//			connector.setPool(pool);
//			Mockito.spy(connector).authenticate("ou=testDn,o=emc", "password1");
//		} catch (Exception e) {
//		}
//	}
//
//	@Test
//	public void testauthenticateAndGetUser() {
//		try {
//			DefaultProxyConnector connector = new DefaultProxyConnector();
//			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//			Entry entry = Mockito.mock(Entry.class);
//			connector.setPool(pool);
//			Mockito.spy(connector).authenticateAndGetUser("ou=testDn,o=emc", "password1");
//		} catch (Exception e) {
//		}
//	}
//
//	@Test
//	public void testmodifyUser() throws LdapException {
//		ModifyRequest modify = Mockito.mock(ModifyRequest.class);
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		Entry entry = Mockito.mock(Entry.class);
//		connector.setPool(pool);
//		Mockito.spy(connector).modifyUser(modify);
//	}
//
//	@Test
//	public void testsearchUser() throws LdapException {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		Entry entry = Mockito.mock(Entry.class);
//		connector.setPool(pool);
//		Mockito.spy(connector).searchUser("ou=testDn,o=emc");
//	}
//
//	@Test
//	public void testmodifyByLdapType() throws LdapException {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//		Entry entry = Mockito.mock(Entry.class);
//		connector.setPool(pool);
//		Mockito.spy(connector).modifyByLdapType("ou=testDn,o=emc", "test1", true, connection);
//		Mockito.spy(connector).modifyByLdapType("ou=testDn,o=emc", "test1", false, connection);
//	}
//
//	@Test
//	public void testchangePassword() {
//		try {
//			DefaultProxyConnector connector = new DefaultProxyConnector();
//			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
//			connector.setPool(pool);
//			assertNotNull(connector.changePassword("ou=testtenant,ou=tenants,o=emc", "test", "test1", true));
//		} catch (Exception e) {
//		}
//	}
//	@Test
//	public void testFilter() {
//		DefaultProxyConnector connector = new DefaultProxyConnector();
//		String reformated = connector.reformatFilterString("(&(objectClass=dsfs)(mail=test@test1.com))");
//		System.out.println("reformated is " + reformated);
//	}
//
//}
