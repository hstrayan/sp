package com.pers.smartproxy;

import static org.junit.Assert.assertNotNull;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.AuthenticationResource;
import com.pers.smartproxy.connectors.EmbeddedConnector;
import com.pers.smartproxy.representations.EndpointConnection;
import com.pers.smartproxy.services.DSEngine;

public class AuthenticationResourceTest {

	private AuthenticationResource auth;

	DSEngine dsEngine;
	@Captor
	ArgumentCaptor<EndpointConnection> argCaptor;
	@Mock
	LdapConnectionPool pool;

	EmbeddedConnector connector;

	private EndpointConnection endpointConnection;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testRegistrationInvocation() {
		dsEngine = new DSEngine();
		connector = new EmbeddedConnector();
		connector.setPool(pool);
		dsEngine.setEmbeddedConnector(connector);
		auth = new AuthenticationResource(dsEngine);
		endpointConnection = new EndpointConnection();
		endpointConnection.setHostName("localhost");
		endpointConnection.setIPAddress("127.0.0.1");
		endpointConnection.setUserName("user");
		endpointConnection.setPassword("password1");
		endpointConnection.setPort(10389);

		assertNotNull(auth.authenticate(endpointConnection));

	}
}
