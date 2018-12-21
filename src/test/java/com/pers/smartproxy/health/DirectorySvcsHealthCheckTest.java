package com.pers.smartproxy.health;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.server.core.api.DirectoryService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.codahale.metrics.health.HealthCheck.Result;
import com.pers.smartproxy.connectors.ProxyConnector;



public class DirectorySvcsHealthCheckTest {

	
	DirectorySvcsHealthCheck dirSvcsHealthCheck;
	Entry entry;
	@Mock
	DirectoryService service;


	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
		
	}

		@Test
	public void testDirSvcsHealth() throws Exception {
			 entry = new DefaultEntry();
			 com.pers.smartproxy.services.DSEngine mock1 = new com.pers.smartproxy.services.DSEngine();
			 mock1.setService(service);
			 Map<String,ProxyConnector> map = new HashMap<String,ProxyConnector>();
			 mock1.setConnectors(map);
			 dirSvcsHealthCheck = new DirectorySvcsHealthCheck(mock1);
			 DirectorySvcsHealthCheck spy = Mockito.spy(dirSvcsHealthCheck);
			 assertNotNull(spy.check());
			 // verify setters/getters
			 dirSvcsHealthCheck.setDsEngine(mock1);
			 assertNotNull(dirSvcsHealthCheck.getDsEngine());
	}

}
