package com.pers.smartproxy.utils;

import static org.junit.Assert.assertNotNull;

import java.util.HashMap;
import java.util.Map;

import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.representations.ConnectorInfo;

public class ConnectionManagerTest {
	
	@Mock
	LdapConnectionPool pool;

	ConnectorInfo connectorInfo;

	@Before
	public void init() {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testConnectionManager() {
		connectorInfo = new ConnectorInfo();
		connectorInfo.setHostname("hostname");
		connectorInfo.setPort(389);
		connectorInfo.setAttributeMap("uid=acctName");
		connectorInfo.setLdapType("apacheDS");
		connectorInfo.setPassword("secret");
		connectorInfo.setReadOnly(true);
		ConnectionManager cm = new ConnectionManager(connectorInfo);
		assertNotNull(cm);

		cm.setPool(pool);
		assertNotNull(cm.getPool());

	}
}
