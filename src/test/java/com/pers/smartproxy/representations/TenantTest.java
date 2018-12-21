package com.pers.smartproxy.representations;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.connectors.ProxyConnector;

public class TenantTest {

	private Tenant tenant;
	@Mock
	private LdapNetworkConnection embeddedConnection;
	@Mock
	private Map<String, ProxyConnector> extConnections;
	@Mock
	Entry entry;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
		tenant = new Tenant();
		tenant.setTenantDn("ou=tenany");
		tenant.setPartitionName("o=emc");
		tenant.setEmbeddedConnection(embeddedConnection);
		tenant.setExtConnections(extConnections);
	}

	@Test
	public void testDoesOuExist() throws Exception {
		Mockito.when(tenant.doesOuExist()).thenReturn(true);
		assertTrue(tenant.doesOuExist());
	}

	@Test
	public void testDoesNotOuExist() throws Exception {
		Mockito.when(tenant.doesOuExist()).thenReturn(false);
		assertFalse(tenant.doesOuExist());
	}

	@Test
	public void testCreateOu() throws Exception {
		String qualifiedDn = tenant.getTenantDn() + "," + tenant.getPartitionName();
		Mockito.doThrow(LdapException.class).when(tenant.getEmbeddedConnection()).add(entry);
		assertTrue(tenant.createTenancyOu(qualifiedDn));
	}

	@Test
	public void testTransformEntryInternal() throws Exception {
		Entry entry = new DefaultEntry("ou=tenant11,ou=tenants,o=emc", "objectClass: inetOrgPerson", "objectClass: top",
				"cn: test", "sn: test", "ou : tenant11");
		Entry updatedEntry = tenant.transformEntryInternal(entry);
		assertNotNull(updatedEntry);
	}

	@Test
	public void testTransformEntryExternal() throws Exception {
		Entry entry = new DefaultEntry("ou=tenant11,ou=tenants,o=emc", "objectClass: inetOrgPerson",
				"objectClass: tenancy", "objectClass: top", "cn: test", "sn: test", "tenantid: xyz", "ou : tenant11");
		String[] sourceString = { "objectClass : top", "objectClass: inetOrgPerson", "cn", "sn", "ou" };
		Map<String, String[]> map = new HashMap<String, String[]>();
		map.put("server2", sourceString);
		Entry updatedEntry = tenant.transformEntryExternal(entry, map);
		assertNotNull(updatedEntry);

	}

	@Test
	public void testTransformEntryExternal2() throws Exception {
		Entry entry = new DefaultEntry("ou=tenant11,ou=tenants,o=emc", "objectClass: inetOrgPerson",
				"objectClass: tenancy", "objectClass: top", "cn: test", "sn: test", "tenantid: xyz", "ou : tenant11");
		Entry updatedEntry = tenant.transformEntryExternal(entry);
		assertNotNull(updatedEntry);

	}

}
