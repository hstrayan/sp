package com.pers.smartproxy;

import static org.junit.Assert.assertNotNull;

import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.codahale.metrics.health.HealthCheck.Result;
import com.codahale.metrics.health.HealthCheckRegistry;

public class HealthCheckResourceTest {

	private HealthCheckResource healthCheckResource;
	@Mock
	private HealthCheckRegistry registry;
	@Mock
	Set<Entry<String, Result>> results;
	@Mock
	SortedMap<String, Result> sortedResults;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testInvocation() {
		healthCheckResource = new HealthCheckResource(registry);
		HealthCheckResource spy = Mockito.spy(healthCheckResource);
		assertNotNull(spy.equals(healthCheckResource));
	}

}
