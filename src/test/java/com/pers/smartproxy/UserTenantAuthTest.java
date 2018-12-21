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
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.connectors.EmbeddedConnector;
import com.pers.smartproxy.representations.EndpointConnection;
import com.pers.smartproxy.representations.User;
import com.pers.smartproxy.services.DSEngine;
import com.pers.smartproxy.utils.LdapCrudUtils;

public class UserTenantAuthTest {

	private UserTenantAuthResource auth;

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
	public void testMappingUsingUserName() {
		// dsEngine = new DSEngine();
		// connector = new EmbeddedConnector();
		// connector.setPool(pool);
		// dsEngine.setEmbeddedConnector(connector);
		auth = new UserTenantAuthResource();
		String userName = "hsathyanarayan1234";
		String sourceNode = "ou=users,ou=tenant71,o=emc";
		String mapping = "uid=samAcctName";
		String fullDn = LdapCrudUtils.createDnForTranslation(userName, sourceNode, mapping);
		assertNotNull(fullDn);

	}

	@Test
	public void testGetTenantName() {
		auth = new UserTenantAuthResource();
		String tenantName = LdapCrudUtils.getTenantFromDn("uid=harish,ou=users,ou=xyz,ou=tenants,o=emc");
		assertNotNull(tenantName);
	}

	@Test
	public void testAuthenticateUser() {
		User user = new User();
		user.setDistinguishedName("o=emc");
		user.setPassword("test");
		auth = new UserTenantAuthResource();
		auth.setDsEngine(dsEngine);
		assertNotNull(auth.authenticateUser(user));
	}

	@Test
	public void testAuthenticateUserExceptions() {
		User user = new User();
		user.setDistinguishedName("");
		user.setPassword("");
		auth = new UserTenantAuthResource();
		auth.setDsEngine(dsEngine);
		assertNotNull(auth.authenticateUser(user));
	}

	@Test
	public void testInstatiation() {
		auth = new UserTenantAuthResource(dsEngine, config);
		assertNotNull(auth);
	}

	@Test
	public void testResolvedUser() throws LdapException {
		Entry entry = new DefaultEntry();
		entry.setDn("o=emc");
		entry.add("cn", "firstname");
		entry.add("sn", "lastname");
		entry.add("email", "test@test.com");

		auth = new UserTenantAuthResource(dsEngine, config);
		User User = auth.resolvedUser(entry);
		assertNotNull(User);
	}

	@Test
	public void testGetUserNameFromDn() throws LdapException {
		auth = new UserTenantAuthResource(dsEngine, config);
		assertNotNull(LdapCrudUtils.getUserNameFromDn("ou=tenants,o=emc"));
	}

	@Test
	public void testgetFirstPartDn() throws LdapException {
		auth = new UserTenantAuthResource(dsEngine, config);
		assertNotNull(LdapCrudUtils.getFirstPartDn("ou=tenants,o=emc"));
	}

	@Test
	public void testgetMappingId() throws LdapException {
		auth = new UserTenantAuthResource(dsEngine, config);
		assertNotNull(auth.getMappingId("uid=samacctname", "uid"));
	}

	@Test
	public void testcreateDnForTranslation() throws LdapException {
		auth = new UserTenantAuthResource(dsEngine, config);
		assertNotNull(LdapCrudUtils.createDnForTranslation("test", "ou=tenants,o=emc", "uid=samacctname,cn=sn"));
	}

}
