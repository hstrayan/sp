package com.pers.smartproxy;

import static org.junit.Assert.assertNotNull;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.connectors.EmbeddedConnector;
import com.pers.smartproxy.representations.EndpointConnection;
import com.pers.smartproxy.representations.Tenancy;
import com.pers.smartproxy.services.DSEngine;

public class TenantResourceTest {

	private TenantResource tenantRes;

	DSEngine dsEngine;
	@Captor
	ArgumentCaptor<EndpointConnection> argCaptor;
	@Mock
	LdapConnectionPool pool;
	@Mock
	EmbeddedConnector connector;
	AppConfig config;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
		dsEngine = new DSEngine();
		config = new AppConfig();
		// connector = new EmbeddedConnector();
		connector.setPool(pool);
		dsEngine.setEmbeddedConnector(connector);
	}

	@Test
	public void testInstatiation() {
		tenantRes = new TenantResource(dsEngine, config);
		assertNotNull(tenantRes);
	}

	@Test
	public void testGetTenantResponse() throws LdapException {
		tenantRes = new TenantResource();
		Entry entry = new DefaultEntry();
		entry.setDn("o=emc");
		entry.add("tenantId", "dfsdfdsf");
		entry.add("sourceTenantDn", "ou=tenants,o=emc");
		entry.add("sourceUsersDn", "ou=users,o=emc");
		entry.add("attrsMap", "uid=samAcctName");
		entry.add("connectionString", "localhost:13389");
		entry.add("readOnly", "true");
		assertNotNull(tenantRes.getTenantResponse(entry));
	}

	@Test
	public void testcreateEntryForSource() throws LdapException {
		tenantRes = new TenantResource();
		Tenancy tenant = new Tenancy();
		tenant.setTenantName("test");
		tenant.setAttrsMap("uid=userId");
		tenant.setConnectionString("localhost:13389:uid=admin,ou=system:test");
		tenant.setSourceTenantDn("ou=tenants,o=emc");
		tenant.setSourceUsersDn("ou=users,o=emc");
		tenant.setReadOnly(true);
		tenantRes.validate(tenant);
		assertNotNull(tenantRes.createEntryForSource(tenant));
	}
	@Test
	public void testAddTenant() throws LdapException {
		tenantRes = new TenantResource();
		tenantRes.setConfiguration(config);
		dsEngine.setEmbedPool(pool);
		tenantRes.setDsEngine(dsEngine);
		
		Tenancy tenant = new Tenancy();
		tenant.setTenantName("test");
		tenant.setAttrsMap("uid=userId");
		tenant.setConnectionString("localhost:13389:uid=admin,ou=system:test");
		tenant.setSourceTenantDn("ou=tenants,o=emc");
		tenant.setSourceUsersDn("ou=users,o=emc");
		tenant.setReadOnly(true);
		assertNotNull(tenantRes.addNewTenant(tenant));
	}
	@Test
	public void tesdeleteTenant()  {
		try{
		String tenantId = "sdfdsfsdfr3324fdf3434";
		tenantRes = new TenantResource();
		tenantRes.setConfiguration(config);
		dsEngine.setEmbedPool(pool);
		tenantRes.setDsEngine(dsEngine);
		assertNotNull(tenantRes.deleteTenant(null));
		assertNotNull(tenantRes.deleteTenant(tenantId));
		}catch(Exception e){}
	}
	@Test
	public void testUpdateTenant()  {
		try{
		String tenantId = "sdfdsfsdfr3324fdf3434";
		tenantRes = new TenantResource();
		tenantRes.setConfiguration(config);
		dsEngine.setEmbedPool(pool);
		tenantRes.setDsEngine(dsEngine);
		Tenancy tenant = new Tenancy();
		tenant.setTenantName("test");
		tenant.setAttrsMap("uid=userId");
		tenant.setConnectionString("localhost:13389:uid=admin,ou=system:test");
		tenant.setSourceTenantDn("ou=tenants,o=emc");
		tenant.setSourceUsersDn("ou=users,o=emc");
		tenant.setReadOnly(true);
		assertNotNull(tenantRes.updateTenant(null,tenant));
		assertNotNull(tenantRes.updateTenant(tenantId,null));
		assertNotNull(tenantRes.updateTenant(tenantId,tenant));
		}catch(Exception e){}
	}
	@Test
	public void testchangeTenantNameLocal()  {
		try{
		tenantRes = new TenantResource();
		tenantRes.setConfiguration(config);
		dsEngine.setEmbedPool(pool);
		tenantRes.setDsEngine(dsEngine);
		Tenancy tenant = new Tenancy();
		tenant.setTenantName("test");
		tenant.setAttrsMap("uid=userId");
		tenant.setConnectionString("localhost:13389:uid=admin,ou=system:test");
		tenant.setSourceTenantDn("ou=tenants,o=emc");
		tenant.setSourceUsersDn("ou=users,o=emc");
		tenant.setReadOnly(true);
		assertNotNull(tenantRes.changeTenantNameLocal(null));
		assertNotNull(tenantRes.changeTenantNameLocal(tenant));
		}catch(Exception e){}
	}
	@Test
	public void testgetAllTenants()  {
		try{
		tenantRes = new TenantResource();
		tenantRes.setConfiguration(config);
		dsEngine.setEmbedPool(pool);
		tenantRes.setDsEngine(dsEngine);
		assertNotNull(tenantRes.getAllTenants());
		}catch(Exception e){}
	}

}
