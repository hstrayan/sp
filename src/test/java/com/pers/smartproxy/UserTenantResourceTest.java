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
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.representations.EndpointConnection;
import com.pers.smartproxy.representations.User;
import com.pers.smartproxy.services.DSEngine;

public class UserTenantResourceTest {

	private UserTenantResource usertenantRes;

	DSEngine dsEngine;
	@Captor
	ArgumentCaptor<EndpointConnection> argCaptor;
	@Mock
	LdapConnectionPool pool;
	@Mock
	EmbeddedConnector connector;
	@Mock
	ProxyConnector proxyConnector;
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
		usertenantRes = new UserTenantResource(dsEngine, config);
		assertNotNull(usertenantRes);
	}

	@Test
	public void testaddUser() throws LdapException {
		usertenantRes = new UserTenantResource();
		usertenantRes.setConfiguration(config);
		dsEngine.setEmbedPool(pool);
		usertenantRes.setDsEngine(dsEngine);

		User user = new User();
		user.setDistinguishedName("o=emc");
		user.setFirstName("firstname");
		user.setLastName("lastname");
		user.setTenantID("teanntId:");
		user.setEmail("test@me.com");
		user.setAddSource(false);
		user.setPassword("test");
		user.setAddSource(true);
		user.setFirstName("firstname");
		assertNotNull(usertenantRes.addUser(user));
	}

	@Test
	public void testcreateAndAddEntryLocal() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");
			usertenantRes.createAndAddEntryLocal(user, "test");
		} catch (Exception e) {
		}
	}

	@Test
	public void testcreateAndAddEntrySource() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");
			usertenantRes.createAndAddEntrySource(user, "test=test", "o=emc", proxyConnector);
		} catch (Exception e) {
		}
	}

	@Test
	public void testvalidateUser() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");
			usertenantRes.validateUser(user);
		} catch (Exception e) {
		}
	}

	@Test
	public void testgetPostMappedDn() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			assertNotNull(usertenantRes.getPostMappedDn("uid=acctName", "ou=users", "testuser"));
		} catch (Exception e) {
		}
	}

	@Test
	public void testisAddToSource() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			Entry entry = new DefaultEntry();
			entry.add("readOnly", "true");
			entry.add("hasSource", "no");

			assertNotNull(usertenantRes.isAddToSource(entry));
		} catch (Exception e) {
		}
	}

	@Test
	public void testsearchUserByUserId() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			assertNotNull(usertenantRes.searchUserByUserId("testuser"));
		} catch (Exception e) {
		}
	}

	@Test
	public void testsearchUserByUserDN() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			assertNotNull(usertenantRes.searchUserByUserDN("ou=user,o=emc"));
		} catch (Exception e) {
		}
	}

	@Test
	public void testdeleteUserByUserId() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			assertNotNull(usertenantRes.deleteUserByUserId("testuser"));
		} catch (Exception e) {
		}
	}

	@Test
	public void testdeleteUser() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");
			assertNotNull(usertenantRes.deleteUser(user));
		} catch (Exception e) {
		}
	}

	@Test
	public void testmodifyUser() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");
			assertNotNull(usertenantRes.modifyUser(user));
		} catch (Exception e) {
		}
	}

	@Test
	public void testtransformEntry() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			Entry entry = new DefaultEntry();
			entry.add("readOnly", "true");
			entry.add("hasSource", "no");

			// assertNotNull(usertenantRes.transformEntry(entry,"ou=ou",
			// "ou=users,o=emc", false));
		} catch (Exception e) {
		}
	}

	@Test
	public void testcreateUserEntry() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");

			assertNotNull(usertenantRes.createUserEntry(user, "secret"));
		} catch (Exception e) {
		}
	}

	@Test
	public void testloadEntry() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");

			assertNotNull(usertenantRes.loadEntry(user));
		} catch (Exception e) {
		}
	}

	@Test
	public void testloadUser() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			Entry entry = new DefaultEntry();
			entry.add("readOnly", "true");
			entry.add("hasSource", "no");

			assertNotNull(usertenantRes.loadUser(entry));
		} catch (Exception e) {
		}
	}

	@Test
	public void testmodifyUserEntry() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");

			assertNotNull(usertenantRes.modifyUserEntry(user, "uid=cn", "o=emc"));
		} catch (Exception e) {
		}
	}

	@Test
	public void testgenerateModifyRequest() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			Entry entry = new DefaultEntry();
			entry.add("readOnly", "true");
			entry.add("hasSource", "no");

			assertNotNull(usertenantRes.generateModifyRequest(entry));
		} catch (Exception e) {
		}
	}

	@Test
	public void testchangePassword() {
		try {
			usertenantRes = new UserTenantResource();
			usertenantRes.setConfiguration(config);
			dsEngine.setEmbedPool(pool);
			usertenantRes.setDsEngine(dsEngine);
			User user = new User();
			user.setDistinguishedName("o=emc");
			user.setFirstName("firstname");
			user.setLastName("lastname");
			user.setTenantID("teanntId:");
			user.setEmail("test@me.com");
			user.setAddSource(false);
			user.setPassword("test");
			user.setAddSource(true);
			user.setFirstName("firstname");

			assertNotNull(usertenantRes.changePassword(user));
		} catch (Exception e) {
		}
	}

	@Test
	public void testTransformedEntry() {
		try {
			String mapping = "mail=email,address=streetaddress";
			Entry baseEntry = new DefaultEntry();
			baseEntry.setDn("ou=tenants,o=emc");
			baseEntry.add("cn", "common name");
			baseEntry.add("sn", "sur name");
			baseEntry.add("mail", "test@test.com");
			baseEntry.add("address", "123 test street, wahtever city");
			baseEntry.add("objectClass", "inetOrgPerson", "organizationalPerson", "person", "top");
			usertenantRes = new UserTenantResource();
			Entry entry = usertenantRes.transformedEntry(mapping, baseEntry, "ou=source,o=emc", false);
			System.out.println(entry.toString());
		} catch (Exception e) {
			System.out.println("exception " + e);
		}
	}
}
