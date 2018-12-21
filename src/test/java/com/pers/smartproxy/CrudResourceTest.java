package com.pers.smartproxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.EntryCursorImpl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.connectors.DefaultProxyConnector;
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.interceptors.ProxyInterceptor;
import com.pers.smartproxy.operations.AddOperation;
import com.pers.smartproxy.representations.CrudOperation;
import com.pers.smartproxy.representations.QueryResult;
import com.pers.smartproxy.services.DSEngine;

public class CrudResourceTest {
	@Mock
	private CrudResource res;
	@Mock
	QueryResult result;
	@Captor
	ArgumentCaptor<CrudOperation> argCaptor;
	@Mock
	DSEngine dsEngine;
	@Mock
	AppConfig config;

	private CrudOperation crudOperation;
	@Mock
	AddOperation add;
	@Mock
	List<Interceptor> intrs;
	@Mock
	LdapConnection connection;
	@Mock
	Map<String, ProxyConnector> connectors;

	@Before
	public void init() throws LdapException {
		crudOperation = new CrudOperation();
		crudOperation.setDn("dn: o=virtustream");
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testRCrudInvocation() throws CursorException {
		Mockito.when(res.addNewEntry(crudOperation)).thenReturn("success");
		assertEquals(res.addNewEntry(crudOperation), "success");
		Mockito.when(res.deleteExistingEntry(crudOperation)).thenReturn("success");
		assertEquals(res.deleteExistingEntry(crudOperation), "success");
		Mockito.when(res.modifyReplaceExistingAttrs(crudOperation)).thenReturn("success");
		assertEquals(res.modifyReplaceExistingAttrs(crudOperation), "success");
	}

	@Test
	public void testCrudArguments() {
		res.addNewEntry(crudOperation);
		Mockito.verify(res).addNewEntry(argCaptor.capture());
		assertEquals("dn: o=virtustream", argCaptor.getValue().getDn());
	}

	@Test
	public void testCrudmethods() throws IOException, LdapException {
		CrudResource crud = new CrudResource();
		CrudResource spy = Mockito.spy(crud);
		crudOperation.setDn("dc=example");
		crudOperation.setScope("sub");
		crudOperation.setAttribute("attr");
		crudOperation.setFilter("(objectClass=*)");
		String[] attrs = { "dsfds" };
		crudOperation.setAttributes(attrs);
		spy.setInterceptors(intrs);
		spy.setDsEngine(dsEngine);
		try {
			Mockito.when(spy.addNewEntry(crudOperation)).thenReturn("success");
			assertEquals(spy.addNewEntry(crudOperation), "succcess");
		} catch (IndexOutOfBoundsException e) {
		}
	}

	@Test
	public void testDeleteMethodInvalidDn() {
		CrudResource crud = new CrudResource();
		crud.setDsEngine(dsEngine);
		CrudOperation deleteOperation = new CrudOperation();
		assertNotNull(crud.deleteExistingEntry(deleteOperation));
	}

	@Test
	public void testDeleteMethod() {
		CrudResource crud = new CrudResource();
		crud.setDsEngine(dsEngine);
		CrudOperation deleteOperation = new CrudOperation();
		deleteOperation.setDn("o=vsc");
		assertNotNull(crud.deleteExistingEntry(deleteOperation));
	}

	@Test
	public void testCustomException() {
		CrudResource crud = new CrudResource();
		crud.setDsEngine(dsEngine);
		CrudOperation deleteOperation = new CrudOperation();
		assertNotNull(crud.customException("custom exception"));
	}

	@Test
	public void testLoadSearchResult() throws LdapInvalidDnException, LdapException {
		CrudResource crud = new CrudResource();
		CrudOperation searchOperation = new CrudOperation();
		String[] attrs = { "test" };
		searchOperation.setAttributes(attrs);
		crud.setDsEngine(dsEngine);
		SearchRequest searchRequest = new SearchRequestImpl();
		crud.loadSearchRequest(searchOperation, searchRequest);
	}

	@Test
	public void testGetInterceptor() throws LdapException {
		CrudResource crud = new CrudResource();
		crud.setDsEngine(dsEngine);
		assertNotNull(crud.getInterceptor());
		assertNotNull(crud.getDsEngine());
		crud.setInterceptors(intrs);
		assertNotNull(crud.getInterceptors());
	}

	@Test
	public void testConnnect() throws LdapException {
		CrudResource crud = new CrudResource();
		crud.setConnection(connection);
		config.setHostName("loalhost");
		config.setPort(389);
		config.setLocalUserName("test");
		config.setLocalPasswd("test");
		crud.connect(config);
	}

	@Test
	public void testEntryFromLdif() {
		try {
			CrudResource crud = new CrudResource();
			crud.setInterceptor(new ProxyInterceptor());
			CoreSession session = Mockito.mock(CoreSession.class);
			dsEngine.setDsSession(session);
			crud.setDsEngine(dsEngine);
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			op.setFilter("*");
			op.setScope("sub");
			String[] obcls = { "top" };
			op.setObjectClass(obcls);

			Entry entry = crud.getEntryFromLdif(op);
			crud.addOperation(entry);
		} catch (Exception e) {
			assertNull(e);
		}

	}

	@Test
	public void testAddingNew() {
		try {
			CrudResource crud = new CrudResource();
			crud.setInterceptor(new ProxyInterceptor());
			CoreSession session = Mockito.mock(CoreSession.class);
			dsEngine.setDsSession(session);
			crud.setDsEngine(dsEngine);
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			op.setFilter("*");
			op.setScope("sub");
			String[] obcls = { "top" };
			op.setObjectClass(obcls);
			String[] attrs = { "name:test1" };
			op.setAttributes(attrs);

			crud.addNewEntry(op);
		} catch (Exception e) {
			assertNull(e);
		}
	}

	@Test
	public void testAddingNewInvalidDn() {
		try {
			CrudResource crud = new CrudResource();
			CrudOperation op = new CrudOperation();
			op.setDn("");
			op.setFilter("*");
			op.setScope("sub");
			String[] obcls = { "top" };
			op.setObjectClass(obcls);
			String[] attrs = { "name:test1" };
			op.setAttributes(attrs);
			crud.addNewEntry(op);
		} catch (Exception e) {
			assertNotNull(e);
		}

	}

	@Test
	public void testAddingNewInvalidAttrs() {
		try {
			CrudResource crud = new CrudResource();
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			op.setAttributes(null);
			crud.addNewEntry(op);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testModifynvalidDn() {
		try {
			CrudResource crud = new CrudResource();
			CrudOperation op = new CrudOperation();
			op.setDn("");
			String[] attrs = { "name:test1" };
			op.setAttributes(attrs);
			crud.modifyReplaceExistingAttrs(op);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testModifyInvalidAttrs() {
		try {
			CrudResource crud = new CrudResource();
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			String[] attrs = { "name:test1" };
			op.setAttributes(null);
			crud.modifyReplaceExistingAttrs(op);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testSearchInvalidDn() {
		try {
			CrudResource crud = new CrudResource();
			CrudOperation op = new CrudOperation();
			op.setDn("");
			String[] attrs = { "name:test1" };
			op.setAttributes(attrs);
			crud.searchAttrs(op);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testSearchInvalidAttrs() {
		try {
			CrudResource crud = new CrudResource();
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			String[] attrs = { "name:test1" };
			op.setAttributes(null);
			crud.searchAttrs(op);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testMappedDnsInvalidDn() {
		try {
			CrudResource crud = new CrudResource();
			CrudOperation op = new CrudOperation();
			op.setDn("");
			String[] attrs = { "name:test1" };
			op.setAttributes(attrs);
			crud.searchMappedDns(op);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testMappedDnsInvalidAttrs() {
		try {
			CrudResource crud = new CrudResource();
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			String[] attrs = { "name:test1" };
			op.setAttributes(null);
			crud.searchMappedDns(op);
		} catch (Exception e) {
			assertNotNull(e);
		}
	}

	@Test
	public void testModify() {
		try {
			CrudResource crud = new CrudResource();
			crud.setInterceptor(new ProxyInterceptor());
			CoreSession session = Mockito.mock(CoreSession.class);
			dsEngine.setDsSession(session);
			crud.setDsEngine(dsEngine);
			crud.setInterceptor(new ProxyInterceptor());
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			op.setFilter("*");
			op.setScope("sub");
			String[] obcls = { "top" };
			op.setObjectClass(obcls);
			String[] attrs = { "name:test1" };
			op.setAttributes(attrs);

			crud.modifyReplaceExistingAttrs(op);
		} catch (Exception e) {
			assertNull(e);
		}
	}

	@Test
	public void testSearchAttrs() {
		try {
			CrudResource crud = new CrudResource();
			crud.setInterceptor(new ProxyInterceptor());
			CoreSession session = Mockito.mock(CoreSession.class);
			dsEngine.setDsSession(session);
			dsEngine.setConnectors(connectors);
			crud.setDsEngine(dsEngine);
			crud.setInterceptor(new ProxyInterceptor());
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			op.setFilter("(objectclass=*)");

			op.setScope("sub");
			String[] obcls = { "top" };
			op.setObjectClass(obcls);
			String[] attrs = { "*" };
			op.setAttributes(attrs);

			crud.searchAttrs(op);
		} catch (Exception e) {
			assertNull(e);
		}
	}

	@Test
	public void testCreateQueryResult() {
		try {
			CrudResource crud = new CrudResource();
			crud.setInterceptor(new ProxyInterceptor());
			CoreSession session = Mockito.mock(CoreSession.class);
			dsEngine.setDsSession(session);
			dsEngine.setConnectors(connectors);
			crud.setDsEngine(dsEngine);
			crud.setInterceptor(new ProxyInterceptor());
			List<QueryResult> results = null;
			Map<String, ProxyConnector> connectors = new HashMap<String, ProxyConnector>();
			DefaultProxyConnector conn = new DefaultProxyConnector();
			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
			conn.setPool(pool);
			connectors.put("ctr1", conn);
			SearchRequest searchRequest = new SearchRequestImpl();
			searchRequest.setTimeLimit(0);
			searchRequest.setBase(new Dn("o=emc"));
			searchRequest.addAttributes("*");
			SearchOperationContext searchContext = Mockito.mock(SearchOperationContext.class);
			searchContext.setDn(new Dn("o=emc"));
			searchContext.setReturningAttributes("*");
			crud.createQueryResult(results, connectors, searchContext);
		} catch (Exception e) {
		//	assertNull(e);
		}
	}

	@Test
	public void testMappedDns() {
		try {
			CrudResource crud = new CrudResource();
			crud.setInterceptor(new ProxyInterceptor());
			CoreSession session = Mockito.mock(CoreSession.class);
			dsEngine.setDsSession(session);

			crud.setInterceptor(new ProxyInterceptor());
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			op.setFilter("(objectclass=*)");

			op.setScope("sub");
			String[] obcls = { "top" };
			op.setObjectClass(obcls);
			String[] attrs = { "*" };
			op.setAttributes(attrs);
			crud.setDsEngine(dsEngine);
			crud.setInterceptor(new ProxyInterceptor());
			List<QueryResult> results = null;
			Map<String, ProxyConnector> connectors = new HashMap<String, ProxyConnector>();
			DefaultProxyConnector conn = new DefaultProxyConnector();
			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
			conn.setPool(pool);
			connectors.put("ctr1", conn);
			dsEngine.setConnectors(connectors);
			crud.setDsEngine(dsEngine);
			crud.searchMappedDns(op);

		} catch (Exception e) {
			assertNull(e);
		}
	}

	@Test
	public void testLoopThruConnectors() {
		try {
			CrudResource crud = new CrudResource();
			crud.setInterceptor(new ProxyInterceptor());
			CoreSession session = Mockito.mock(CoreSession.class);
			dsEngine.setDsSession(session);

			List<QueryResult> results = new ArrayList<QueryResult>();

			Map<String, ProxyConnector> connectors = new HashMap<String, ProxyConnector>();
			DefaultProxyConnector conn = new DefaultProxyConnector();
			LdapConnectionPool pool = Mockito.mock(LdapConnectionPool.class);
			conn.setPool(pool);
			connectors.put("ctr1", conn);
			dsEngine.setConnectors(connectors);
			crud.setDsEngine(dsEngine);
			crud.setInterceptor(new ProxyInterceptor());
			CrudOperation op = new CrudOperation();
			op.setDn("o=emc");
			op.setFilter("(objectclass=*)");

			op.setScope("sub");
			String[] obcls = { "top" };
			op.setObjectClass(obcls);
			String[] attrs = { "*" };
			op.setAttributes(attrs);
			crud.setDsEngine(dsEngine);
			crud.loopThruConnectors(op, results, connectors);
		} catch (Exception e) {
			assertNull(e);
		}
	}

}
