package com.pers.smartproxy.connectors;
//package com.virtustream.coreservices.rolodex.connectors;
//
//import static org.junit.Assert.assertEquals;
//import static org.junit.Assert.assertNotNull;
//
//import org.apache.directory.api.ldap.model.cursor.CursorException;
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.apache.directory.api.ldap.model.message.ModifyRequest;
//import org.apache.directory.ldap.client.api.DefaultPoolableLdapConnectionFactory;
//import org.apache.directory.ldap.client.api.LdapConnection;
//import org.apache.directory.ldap.client.api.LdapConnectionConfig;
//import org.apache.directory.ldap.client.api.LdapConnectionPool;
//import org.junit.Before;
//import org.junit.Test;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//
//import com.virtustream.coreservices.rolodex.representations.Tenancy;
//import com.virtustream.coreservices.rolodex.representations.User;
//
//import static org.junit.Assert.assertEquals;
//import static org.junit.Assert.assertNotNull;
//
//import org.apache.directory.api.ldap.model.cursor.CursorException;
//import org.apache.directory.api.ldap.model.entry.DefaultEntry;
//import org.apache.directory.api.ldap.model.entry.Entry;
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.apache.directory.api.ldap.model.message.ModifyRequest;
//import org.apache.directory.api.ldap.model.name.Dn;
//
//public class EmbeddedConnectorTest {
//
//	@Mock
//	private EmbeddedConnector embeddedConnector;
//
//	@Mock
//	private LdapConnection connection;
//	@Mock
//	private LdapConnectionPool pool;
//	@Mock
//	private DefaultPoolableLdapConnectionFactory factory;
//	@Mock
//	private LdapConnectionConfig config;
//
//	@Before
//	public void init() throws LdapException {
//		MockitoAnnotations.initMocks(this);
//	}
//
//	@Test
//	public void testEmbeddedConnector() throws LdapException, CursorException {
//		Mockito.when(embeddedConnector.getLocalHost()).thenReturn("127.0.0.1");
//		assertEquals(embeddedConnector.getLocalHost(), "127.0.0.1");
//
//		Mockito.when(embeddedConnector.getPort()).thenReturn(10389);
//		assertEquals(embeddedConnector.getPort(), 10389);
//
//		Mockito.when(embeddedConnector.connect("127.0.0.1", 10389, "user", "pwd")).thenReturn(true);
//		assertEquals(embeddedConnector.connect("127.0.0.1", 10389, "user", "pwd"), true);
//	}
//
//	@Test
//	public void testSettersGetters() {
//		EmbeddedConnector connector = new EmbeddedConnector();
//		connector.setLocalHost("localhost");
//		connector.setPort(389);
//		assertEquals(connector.getLocalHost(), "localhost");
//		assertEquals(connector.getPort(), 389);
//
//	}
//
//	@Test
//	public void testConnectionPool() {
//		try {
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.configurePool();
//		} catch (Exception e) {
//			assertNotNull(e);
//		}
//
//	}
//
//	@Test
//	public void testConnection() {
//		try{
//		EmbeddedConnector connector = new EmbeddedConnector();
//		connector.setPool(pool);
//		connector.setConfig(config);
//		connector.setFactory(factory);
//		connector.connect("localhost", 389, "name", "secret");
//		}catch(Exception e){}
//
//	}
//	
//	@Test
//	public void testlookUpTenantByDn() {
//		try{
//		EmbeddedConnector connector = new EmbeddedConnector();
//		connector.setPool(pool);
//		connector.setConfig(config);
//		connector.setFactory(factory);
//		assertNotNull(connector.lookUpTenantByDn("ou=tenant1,ou=tenants,o=emc"));
//		}catch(Exception e){}
//	}
//		
//	@Test
//	public void testretrieveAllTenants() {
//		try{
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.retrieveAllTenants());
//			}catch(Exception e){}
//	}
//	@Test
//	public void testsearchTenantByAttr() {
//		try{
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.searchTenantByAttr("tenantId", "testtenant"));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testAddTenant() {
//		try{
//			Entry tenant = Mockito.mock(Entry.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.addTenant(tenant));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testAddUser() {
//		try{
//			Entry user = Mockito.mock(Entry.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			connector.addUser(user);
//			}catch(Exception e){}
//	}
//	@Test
//	public void testgetUserEntry() {
//		try{
//			Entry tenant = Mockito.mock(Entry.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.getUserEntry("ou=tenant,ou=tenants,o=emc"));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testgetGroupEntry() {
//		try{
//			Entry tenant = Mockito.mock(Entry.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.getGroupEntry("ou=tenant,ou=tenants,o=emc"));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testaddSubTenantOUs() {
//		try{
//			Entry tenant = Mockito.mock(Entry.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			connector.addSubTenantOUs(tenant);
//			}catch(Exception e){}
//	}
//	@Test
//	public void testgetEntryFromTenantObj() {
//		try{
//			Tenancy tenant = new Tenancy();
//			tenant.setTenantName("testtenant");
//			tenant.setSourceTenantDn("ou=tenants,o=emc");
//			tenant.setSourceUsersDn("ou=users");
//			tenant.setAttrsMap(" ");
//			tenant.setLdapType("ads");
//			tenant.setReadOnly(true);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.getEntryFromTenantObj(tenant));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testdeleteTenantByAttr() {
//		try{
//			Entry tenant = Mockito.mock(Entry.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.deleteTenantByAttr(new Dn("ou=testtenant,ou=tenants,o=emc")));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testdeleteByDn() {
//		try{
//			Entry tenant = Mockito.mock(Entry.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.deleteByDn(new Dn("ou=testtenant,ou=tenants,o=emc")));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testcascadeDeleteTenantByAttr() {
//		try{
//			Entry tenant = Mockito.mock(Entry.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.cascadeDeleteTenantByAttr(new Dn("ou=testtenant,ou=tenants,o=emc")));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testmodifyTenant() {
//		try{
//			Tenancy tenant = Mockito.mock(Tenancy.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.modifyTenant("ou=testtenant,ou=tenants,o=emc", tenant));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testchangePassword() {
//		try{
//			Tenancy tenant = Mockito.mock(Tenancy.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.changePassword("ou=testtenant,ou=tenants,o=emc", "test","test1"));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testModifyBasedonPwdType() {
//		try{
//			User user = new User();
//			user.setSourcePwdUnicode(true);
//			Tenancy tenant = Mockito.mock(Tenancy.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			connector.modifyBasedonPwdType("ou=testtenant,ou=tenants,o=emc", "test",connection,new User());
//			connector.modifyBasedonPwdType("ou=testtenant,ou=tenants,o=emc", "test",connection,user);
//			}catch(Exception e){}
//		}
//	@Test
//	public void testloadUser() {
//		try{
//			Entry tenant = new DefaultEntry();
//			tenant.setDn("o=test");
//			tenant.add("cn","testcn");
//			tenant.add("sn","testsn");
//			tenant.add("uid","testuid");
//			tenant.add("mail","mail");
//			tenant.add("tenantId","tenantId");
//			tenant.add("unicodePwd","unicodePwd");
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.loadUser(tenant));
//			}catch(Exception e){}
//		}
//	@Test
//	public void testdeleteUserByUserId() {
//		try{
//			Tenancy tenant = Mockito.mock(Tenancy.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.deleteUserByUserId("testuser"));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testmodifyUser() {
//		try{
//			ModifyRequest modify = Mockito.mock(ModifyRequest.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			assertNotNull(connector.modifyUser(modify));
//			}catch(Exception e){}
//	}
//	@Test
//	public void testlookUpUserByDn() {
//		try{
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			connector.lookUpUserByDn("ou=testtenant,o=emc");
//			}catch(Exception e){}
//	}
//	@Test
//	public void testlookUpUserByUID() {
//		try{
//		    EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			connector.lookUpUserByUID("uid");
//			}catch(Exception e){}
//	}
//	@Test
//	public void testlookUpUserEntryByDn() {
//		try{
//			ModifyRequest modify = Mockito.mock(ModifyRequest.class);
//			EmbeddedConnector connector = new EmbeddedConnector();
//			connector.setPool(pool);
//			connector.setConfig(config);
//			connector.setFactory(factory);
//			connector.lookUpUserEntryByDn("ou=testtenant,o=emc");
//			}catch(Exception e){}
//	}
//
//}
