package com.pers.smartproxy;
//package com.virtustream.coreservices.rolodex;
//
//import static org.junit.Assert.assertEquals;
//import static org.mockito.Mockito.when;
//
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.junit.Before;
//import org.junit.Test;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//
//import io.dropwizard.jersey.setup.JerseyEnvironment;
//import io.dropwizard.setup.Bootstrap;
//import io.dropwizard.setup.Environment;
//
//public class BootupAppTest {
//
//	@Mock
//	Environment env;
//	@Mock
//	JerseyEnvironment jersey;
//	@Mock
//	CrudResource crud;
//	@Mock
//	AppConfig configuration;
//	@Mock
//	Bootstrap<AppConfig> bootstrap;
//	
//	BootupApp bootup;
//	
//	@Before
//	public void init() throws LdapException {
//		MockitoAnnotations.initMocks(this);
//	}
//
//	@Test
//	public void testJerseyInvocation() throws Exception {
//		when(env.jersey()).thenReturn(jersey);
//		assertEquals(jersey, env.jersey());
//	}
//	@Test
//	public void testMethods() throws Exception {
//		bootup = new BootupApp();
//		BootupApp spy = Mockito.spy(bootup);
//		spy.initialize(bootstrap);
//		Mockito.doCallRealMethod().doThrow(new NullPointerException("one")).when(spy).run(configuration,env);
//	}
//	
//
//}
