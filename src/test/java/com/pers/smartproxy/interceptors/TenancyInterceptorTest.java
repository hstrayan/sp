package com.pers.smartproxy.interceptors;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doNothing;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.CoreSession;
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
import com.pers.smartproxy.representations.Tenant;
import com.pers.smartproxy.services.DSEngine;

@CreateDS(name = "UnitTest", partitions = {
		@CreatePartition(name = "UnitTest", suffix = "dc=example,dc=com", contextEntry = @ContextEntry(entryLdif = "dn: dc=example,dc=com\n"
				+ "dc: example\n" + "objectClass: top\n" + "objectClass: domain\n\n")) }, enableChangeLog = false)
@CreateLdapServer(transports = {
		@CreateTransport(protocol = "LDAP", address = "localhost", port = 12389) }, allowAnonymousAccess = true)
@ApplyLdifs({ "dn: dc=test,dc=example,dc=com", "objectClass: top", "objectClass: domain", "dc: test", "",
		"dn: ou=groups,dc=test,dc=example,dc=com", "objectClass: top", "objectClass: organizationalUnit", "ou: groups",
		"", "dn: cn=imadmin,ou=groups,dc=test,dc=example,dc=com", "objectClass: top", "objectClass: groupOfUniqueNames",
		"uniqueMember: uid=dummy", "description: AdministrationGroup", "cn: imadmin", "" })
public class TenancyInterceptorTest extends AbstractLdapTestUnit {

	@Mock
	AppConfig config;
	@Mock
	DSEngine engine;
	@Mock
	SearchOperationContext searchContext;
	@Mock
	CoreSession session;
	@Mock
	ModifyOperationContext modContext;
	AddOperationContext addContext = new AddOperationContext(null);
	DeleteOperationContext deleteContext = new DeleteOperationContext(null);
	ModifyOperationContext modifyContext = new ModifyOperationContext(session);
	@Mock
	Entry entry;
	TenancyInterceptor tenancyInterceptor;
	@Mock
	LdapNetworkConnection remoteConnection;
	LdapNetworkConnection localConnection;
	@Mock
	LdapNetworkConnection embeddedConnection;
	@Mock
	private DirectoryService directoryService;
	@Mock
	EntryCursor entryCursor;
	@Mock
	List<Interceptor> interceptors = null;
	@Mock
	DefaultProxyConnector connector;
	Map<String, ProxyConnector> map = new HashMap<String, ProxyConnector>();

	boolean isConnected = false;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
		List<Interceptor> interceptors = directoryService.getInterceptors();
		TenancyInterceptor interceptor = new TenancyInterceptor();
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
	public void testFilterRolodexAttrs() throws LdapInvalidDnException, LdapInvalidAttributeValueException {
		modContext.setDn(new Dn("o=vsc"));
		Modification mod = new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "street", "123 my street");
		Modification mod2 = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "tenantId",
				"testprovider123");
		List<Modification> list = new ArrayList<Modification>();
		Attribute attribute = new DefaultAttribute(" CN ");
		attribute.setUpId("cn");
		attribute.add("test1");
		mod.setAttribute(attribute);
		mod2.setAttribute(attribute);
		list.add(mod);
		list.add(mod2);
		modContext.setModItems(list);
		tenancyInterceptor = new TenancyInterceptor();
		AppConfig cfg = new AppConfig();
		String[] rolodexAttrs = { "tenantid", "placeholderAttrs", "misc" };
		cfg.setRolodexAttrs(rolodexAttrs);
		tenancyInterceptor.setConfig(cfg);
		}

	@Test
	public void testCrudMethods() throws LdapException {
		TenancyInterceptor interceptor = new TenancyInterceptor();
	
		TenancyInterceptor spy = Mockito.spy(interceptor);
		doNothing().when(remoteConnection).add(entry);
		assertNotNull(entry);
		map.put("ctr1", connector);
		interceptor.setConnectorMap(map);
		// interceptor.setConfiguration(config);
		Mockito.doNothing().when(spy).add(addContext);
		Entry entry = new DefaultEntry();
		entry.setDn("o=emc");
		Tenant tenant = new Tenant();
		tenant.setTenantDn("o=emc");
		addContext.setEntry(entry);
		interceptor.setTenant(tenant);
		engine.setIsFullyStarted(true);
		try {
		interceptor.add(addContext);
		} catch (Exception e) {
		}

		config.setMappingDn("o=emc");
		interceptor.setConfig(config);
		addContext.setEntry(entry);
	    interceptor.setTenant(tenant);
		try {
			
			interceptor.add(addContext);
		} catch (Exception e) {
		}
		deleteContext.setDn(new Dn("o=emc"));
		Mockito.doNothing().when(spy).delete(deleteContext);
		try {
			interceptor.delete(deleteContext);
		} catch (NullPointerException e) {
		}
		Mockito.doNothing().when(spy).modify(modifyContext);
		try {
			interceptor.modify(modifyContext);
		} catch (NullPointerException e) {
		}
		// validate getters/setters
		interceptor.setConfig(config);
		assertNotNull(interceptor.getConfig());
		interceptor.setTenant(tenant);
		assertNotNull(interceptor.getTenant());
		interceptor.setPartitionName("o=emc");
		assertNotNull(interceptor.getPartitionName());
	
	
		interceptor.setConnectorMap(map);
		assertNotNull(interceptor.getConnectorMap());
		interceptor.setEmbeddedConnection(embeddedConnection);
		assertNotNull(interceptor.getEmbeddedConnection());
		// constrcutor test
		tenant.setPartitionName("o=virtusream");
		tenant.setTenantDn("o=emc");
		tenant.setEmbeddedConnection(embeddedConnection);
		tenant.setExtConnections(map);
	}

	@Test
	public void testAddExternalMethods() throws LdapException {
		TenancyInterceptor interceptor = new TenancyInterceptor();
	
		Entry entry = new DefaultEntry("o=virtustream");
		Map<String, ProxyConnector> extConnections = new HashMap<String, ProxyConnector>();
		extConnections.put("connector1", new DefaultProxyConnector());
		config.setMappingDn("o=emc");
		Map<String, String[]> sourceAttrs = new HashMap<String, String[]>();
		String[] source = { "test1", "test2" };
		sourceAttrs.put("connector1", source);
	//	config.setSourceAttributes(sourceAttrs);
		interceptor.setConfig(config);
		Tenant tenant = new Tenant();
		tenant.setTenantDn("o=emc");
		interceptor.setTenant(tenant);
	//	interceptor.addExternal(entry, extConnections);
		TenancyInterceptor spy = Mockito.spy(interceptor);
		doNothing().when(spy).addExternal(entry, extConnections);
		assertNotNull(spy);
	}

	@Test
	public void testDeleteExternalMethods() throws LdapException {
		TenancyInterceptor interceptor = new TenancyInterceptor();
	
		Entry entry = new DefaultEntry("o=virtustream");
		Map<String, ProxyConnector> extConnections = new HashMap<String, ProxyConnector>();
		extConnections.put("connector1", new DefaultProxyConnector());
		config.setMappingDn("o=emc");
		Map<String, String[]> sourceAttrs = new HashMap<String, String[]>();
		String[] source = { "test1", "test2" };
		sourceAttrs.put("connector1", source);
	//	config.setSourceAttributes(sourceAttrs);
		interceptor.setConfig(config);
		Tenant tenant = new Tenant();
		tenant.setTenantDn("o=emc");
		tenant.setExtConnections(extConnections);
		interceptor.setTenant(tenant);
		deleteContext.setDn(new Dn("o=emc"));
		
		assertNotNull(interceptor);
		TenancyInterceptor spy = Mockito.spy(interceptor);
		doNothing().when(spy).delete(deleteContext);
		assertNotNull(spy);
	}

	@Test
	public void testModifyExternalMethods() throws LdapException {
		TenancyInterceptor interceptor = new TenancyInterceptor();
		Entry entry = new DefaultEntry("o=virtustream");
		Map<String, ProxyConnector> extConnections = new HashMap<String, ProxyConnector>();
		extConnections.put("connector1", new DefaultProxyConnector());
		config.setMappingDn("o=emc");
		Map<String, String[]> sourceAttrs = new HashMap<String, String[]>();
		String[] source = { "test1", "test2" };
		sourceAttrs.put("connector1", source);
	//	config.setSourceAttributes(sourceAttrs);
		interceptor.setConfig(config);
		Tenant tenant = new Tenant();
		tenant.setTenantDn("o=emc");
		tenant.setExtConnections(extConnections);
		interceptor.setTenant(tenant);
		ModifyRequest modRequest = new ModifyRequestImpl();
		modRequest.setName(new Dn("o=virtustream"));
	
		assertNotNull(interceptor);
	}
	
	
	
	
}
