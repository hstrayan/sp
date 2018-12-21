package com.pers.smartproxy.health;

import static org.junit.Assert.assertNotNull;

import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.junit.Test;
import org.mockito.Mockito;

import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.services.DSEngine;


public class ExtConnectorsHealthCheckTest {

	ExtConnectorsHealthCheck extConnectorsHealthCheck;
	Entry entry;

	@Test
	public void testExtConnectorsHealth() throws Exception {
		 entry = new DefaultEntry();
		 DSEngine mock1 = new DSEngine();
		 Map<String,ProxyConnector> map = new HashMap<String,ProxyConnector>();
		 mock1.setConnectors(map);
		 extConnectorsHealthCheck = new ExtConnectorsHealthCheck(mock1);
		 ExtConnectorsHealthCheck spy = Mockito.spy(extConnectorsHealthCheck);
		 assertNotNull(spy.check());
	}

}
