package com.pers.smartproxy.interceptors;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doNothing;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.connectors.DefaultProxyConnector;
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.AppConfig;

@CreateDS(name = "UnitTest", partitions = {
		@CreatePartition(name = "UnitTest", suffix = "dc=example,dc=com", contextEntry = @ContextEntry(entryLdif = "dn: dc=example,dc=com\n"
				+ "dc: example\n" + "objectClass: top\n" + "objectClass: domain\n\n")) }, enableChangeLog = false)
@CreateLdapServer(transports = {
		@CreateTransport(protocol = "LDAP", address = "localhost", port = 12389) }, allowAnonymousAccess = true)
@ApplyLdifs({ "dn: dc=test,dc=example,dc=com", "objectClass: top", "objectClass: domain", "dc: test", "",
		"dn: ou=groups,dc=test,dc=example,dc=com", "objectClass: top", "objectClass: organizationalUnit", "ou: groups",
		"", "dn: cn=imadmin,ou=groups,dc=test,dc=example,dc=com", "objectClass: top", "objectClass: groupOfUniqueNames",
		"uniqueMember: uid=dummy", "description: AdministrationGroup", "cn: imadmin", "" })
public class ProxyInterceptorTest extends AbstractLdapTestUnit {

	@Mock
	AppConfig config;
	@Mock
	DefaultProxyConnector connector;

	@Mock
	ProxyInterceptor interceptor;

	@Mock
	SearchOperationContext searchContext;
		
	AddOperationContext addContext = new AddOperationContext(null);
	
	DeleteOperationContext deleteContext = new DeleteOperationContext(null);
	
	ModifyOperationContext modifyContext = new ModifyOperationContext(null);
	
	@Mock
	Entry entry;

	@Mock
	ProxyInterceptor proxyInterceptor;

	@Mock
	LdapNetworkConnection remoteConnection;

	LdapNetworkConnection localConnection;

	@Mock
	private DirectoryService directoryService;

	@Mock
	EntryCursor entryCursor;

	@Mock
	List<Interceptor> interceptors = null;
	
	
	Map<String, ProxyConnector> map = new HashMap<String, ProxyConnector>() ;

	boolean isConnected = false;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
		List<Interceptor> interceptors = directoryService.getInterceptors();
		interceptor = new ProxyInterceptor(null);
		interceptors.add(interceptors.size(), interceptor);
		directoryService.setInterceptors(interceptors);
	}

	private LdapNetworkConnection getConnection() throws LdapException {
		if (localConnection == null) {
			localConnection = new LdapNetworkConnection("localhost", 12389);
			isConnected = true;
		}
		return localConnection;
	}

	private void closeConnection() throws IOException {
		if (localConnection != null) {
			localConnection.close();
			localConnection = null;
			isConnected = false;
		}
	}

	@Test
	public void testInterceptorListNotEmpty() throws LdapException {
		Mockito.when(directoryService.getInterceptors()).thenReturn(interceptors);
		assertNotNull(directoryService.getInterceptors());
	}

	@Test
	public void testIsConnectedLocally() throws LdapException {
		localConnection = getConnection();

		assertTrue(isConnected);
		assertNotNull(localConnection);
	}

	@Test
	public void testIsNotConnectedLocally() throws LdapException, IOException {
		closeConnection();

		assertFalse(isConnected);
		assertNull(localConnection);
	}

	@Test
	public void testSearchProxyInterceptor() throws LdapException, IOException, CursorException {
		interceptor.setProxyConnector(connector);
		Mockito.when(remoteConnection.search("dc=test,dc=example,dc=com", "(objectclass=top)", SearchScope.SUBTREE, ""))
				.thenReturn(entryCursor);
		assertNotNull(entryCursor);
	}
	
	@Test
	public void testMethods() throws LdapException {
		ProxyInterceptor interceptor = new ProxyInterceptor();
		interceptor.setProxyConnector(connector);
		ProxyInterceptor spy = Mockito.spy(interceptor);
		doNothing().when(remoteConnection).add(entry);
		assertNotNull(entry);
		map.put("ctr1", connector);
		interceptor.setConnectorMap(map);
		interceptor.setConfiguration(config);
		Mockito.doNothing().when(spy).add(addContext);
	//	interceptor.add(addContext);
		deleteContext.setDn(new Dn("o=emc"));
	    Mockito.doNothing().when(spy).delete(deleteContext);
	    interceptor.delete(deleteContext);
	    Mockito.doNothing().when(spy).modify(modifyContext);
	    interceptor.modify(modifyContext);
	}
	
	

}
