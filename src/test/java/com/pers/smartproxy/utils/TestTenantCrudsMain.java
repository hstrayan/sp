package com.pers.smartproxy.utils;
//package com.virtustream.coreservices.rolodex.utils;
//
//import java.io.IOException;
//
//import javax.naming.ldap.Control;
//
//import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyDecorator;
//import org.apache.directory.api.ldap.model.cursor.CursorException;
//import org.apache.directory.api.ldap.model.cursor.EntryCursor;
//import org.apache.directory.api.ldap.model.cursor.SearchCursor;
//import org.apache.directory.api.ldap.model.entry.DefaultEntry;
//import org.apache.directory.api.ldap.model.entry.DefaultModification;
//import org.apache.directory.api.ldap.model.entry.Entry;
//import org.apache.directory.api.ldap.model.entry.Modification;
//import org.apache.directory.api.ldap.model.entry.ModificationOperation;
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.apache.directory.api.ldap.model.message.BindRequest;
//import org.apache.directory.api.ldap.model.message.BindRequestImpl;
//import org.apache.directory.api.ldap.model.message.BindResponse;
//import org.apache.directory.api.ldap.model.message.DeleteRequest;
//import org.apache.directory.api.ldap.model.message.DeleteRequestImpl;
//import org.apache.directory.api.ldap.model.message.ModifyRequest;
//import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
//import org.apache.directory.api.ldap.model.message.Response;
//import org.apache.directory.api.ldap.model.message.SearchRequest;
//import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
//import org.apache.directory.api.ldap.model.message.SearchResultEntry;
//import org.apache.directory.api.ldap.model.message.SearchScope;
//import org.apache.directory.api.ldap.model.message.controls.ManageDsaITImpl;
//import org.apache.directory.api.ldap.model.message.controls.ProxiedAuthzImpl;
//import org.apache.directory.api.ldap.model.name.Dn;
//import org.apache.directory.ldap.client.api.LdapConnection;
//import org.apache.directory.ldap.client.api.LdapNetworkConnection;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//
//import com.virtustream.coreservices.rolodex.connectors.EmbeddedConnector;
//
///**
// * @author sathyh2
// * 
// * 
// *         This is a testdriver class to run Tenancy related CRUD operations.
// *         This is an example and the values needs to be changed based on the
// *         environment - docker container IP, LDAP Server names etc
// * 
// *
// */
//public class TestTenantCrudsMain {
//
//	final Logger logger = LoggerFactory.getLogger(TestTenantCrudsMain.class);
//	private EmbeddedConnector connector;
//	private static final String HOSTNAME = "192.168.99.101";
//	private static final int PORT = 10389;
//	private static final String USERNAME = "uid=admin,ou=system";
//	private static final String PWD = "secret";
//
//	/**
//	 * Constructor
//	 */
//	public TestTenantCrudsMain() {
//		connector = new EmbeddedConnector();
//	}
//
//	/**
//	 * Add Entry
//	 * 
//	 * @param entry
//	 */
//	void testAddEntry(Entry entry) {
//		try {
//			LdapConnection connection = getConnection(connector);
//			connection.add(entry);
//			closeConnection(connection);
//		} catch (LdapException e) {
//			logger.info(e.getMessage());
//		}
//	}
//
//	/**
//	 * Delete Dn
//	 * 
//	 * @param deleteDn
//	 * @throws LdapException 
//	 */
//	void testDeleteEntry(String deleteDn) throws LdapException {
//		LdapConnection connection = getConnection(connector);
//		try {
//			connection.delete(deleteDn);
//		} catch (LdapException e) {
//			logger.info(e.getMessage());
//		}
//		closeConnection(connection);
//	}
//
//	/**
//	 * Search Dn
//	 * 
//	 * @param searchDn
//	 * @throws LdapException 
//	 */
//	void testSearchEntry(String req) throws LdapException {
//		LdapConnection connection = getConnection(connector);
//		EntryCursor cursor = null;
//		try {
//			cursor = connection.search("ou=deadbolt,ou=tenants,o=emc", "(&(objectClass=tenancy)(mail=deadbolt.admin@virtustream.com))", SearchScope.SUBTREE);
//			 while ( cursor.next() )
//			    {
//			       Entry entry = cursor.get();
//			       System.out.println(entry.getDn().getName());
//
//			    }
//		} catch (LdapException | CursorException e) {
//			logger.info(e.getMessage());
//		}
//		closeConnection(connection);
//	}
//
//	/**
//	 * Search Dn
//	 * 
//	 * @param searchDn
//	 * @throws LdapException 
//	 */
//	void lookUpEntry(String searchDn) throws LdapException {
//		LdapConnection connection = getConnection(connector);
//		try {
//			Entry entry = connection.lookup(new Dn(searchDn));
//			System.out.println("entry is " + entry);
//			
//		} catch (LdapException e) {
//			logger.info(e.getMessage());
//		}
//		closeConnection(connection);
//	}
//
//	private void bind(String string) {
//		// TODO Auto-generated method stub
//		LdapConnection connection = null;
//	try{
//			connection = getConnection(connector);
//		
//			BindRequest req = new BindRequestImpl();
//			req.setDn(new Dn(string));
//			req.setCredentials("test");
//			req.setSimple(true);
//			BindResponse res = connection.bind(req);
//		
//			System.out.println(res.getLdapResult().getResultCode());
//			if (connection.isAuthenticated()) System.out.println("bind is success");
//			
//		closeConnection(connection);
//	}catch(Exception e){
//	//	e.printStackTrace();
//	}
//		
//	}
//	
//	/**
//	 * Modify Entry
//	 * 
//	 * @param modifyRequest
//	 */
//	void testModifyEntry(ModifyRequest modifyRequest) {
//		try {
//			LdapConnection connection = getConnection(connector);
//			connection.modify(modifyRequest);
//			closeConnection(connection);
//		} catch (LdapException e) {
//			logger.info(e.getMessage());
//		}
//	}
//
//	/**
//	 * Get connection
//	 * 
//	 * @param connector
//	 * @return
//	 * @throws LdapException 
//	 */
////	private LdapConnection getConnection(EmbeddedConnector connector) throws LdapEaxception {
//		
//		if(connector.connect(HOSTNAME, PORT, USERNAME, PWD)) {
//			return connector.getPool().getConnection();
//		}
//		return null;
//	}
//
//	/**
//	 * Close connection
//	 * 
//	 * @param connection
//	 */
//	private void closeConnection(LdapConnection connection) {
//		try {
//			connection.close();
//		} catch (IOException e) {
//			logger.info(e.getMessage());
//		}
//	}
//
//	/**
//	 * Perform CRUD operations using example data
//	 * 
//	 * @param args
//	 * @throws LdapException
//	 * @throws IOException
//	 * @throws CursorException
//	 */
//	public static void main(String[] args) throws LdapException, IOException, CursorException {
//
//		if (args.length == 0) {
//			System.out.println(" invalid input args: use ADD or MODIFY or SEARCH or DELETE");
//			System.exit(0);
//		}
//		TestTenantCrudsMain testTenantCrudsMain = new TestTenantCrudsMain();
//		if (args[0].equalsIgnoreCase("ADD")) {
//			
//			Entry addtenantEntryEntry = new DefaultEntry(
//				            "ou=deadbolt,ou=tenants,o=emc",
//				            "objectClass: top", 
//				            "objectClass: tenancy",
//				            "objectClass: organizationalUnit",
//						    "sourceTenantDn: ou=tenants,dc=deadbolt,dc=emc",
//						    "sourceUsersDn: ou=deadbolt,ou=tenants,dc=deadbolt,dc=emc",
//						    "attrsMap:description=mail",
//						    "readOnly: false",
//						    "resourcesetid: gdfgfd234234234fdf32432",
//						    "ldapType: openLdap");
//			
//			
//			Entry userEntry =  new DefaultEntry(
//					  "uid=exampleuser,ou=users,ou=deadbolt,ou=tenants,o=emc",
//			            "objectClass: top", 
//			            "objectClass: tenancy",
//			            "objectClass: organizationalPerson",
//			            "objectClass: inetOrgPerson",
//			            "tenantId: fd351c6c-a79a-4cb2-a4bc-784273cba4b4",
//			            "cn: firstname",
//			            "sn: lastname",
//			            "description: test desc",
//			            "mail: test@test.com",
//			            "tempPwd: test");
//			Entry ou =  new DefaultEntry(
//					"ou=users,ou=deadbolt,ou=tenants,o=emc",
//					 "objectClass: top", 
//					 "objectClass: tenancy",
//					 "objectClass: organizationalUnit"
//					);
//			
//					testTenantCrudsMain.testAddEntry(ou);
//			}
//		
//		
//		if (args[0].equalsIgnoreCase("MODIFY")) {
//			ModifyRequest modRequest = new ModifyRequestImpl();
//			modRequest.setName(new Dn("uid=exampleuser,ou=users,ou=tenant206,ou=tenants,o=emc"));
//			Modification mod = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "description","test@blbh.com");
//			modRequest.addModification(mod);
//			testTenantCrudsMain.testModifyEntry(modRequest);
//		}
//		if (args[0].equalsIgnoreCase("SEARCH")) {
//			
//			testTenantCrudsMain.testSearchEntry("ou=deadbolt,ou=tenants,o=emc");
//		}
//		if (args[0].equalsIgnoreCase("DELETE")) {
//			testTenantCrudsMain.testDeleteEntry("uid=exampleuser,ou=users,ou=test,ou=tenants,o=emc");
//		}
//		if (args[0].equalsIgnoreCase("LOOKUP")) {
//			testTenantCrudsMain.lookUpEntry("ou=users,ou=deadbolt,ou=tenants,o=emc");
//		}
//		if (args[0].equalsIgnoreCase("BIND")) {
//			testTenantCrudsMain.bind("uid=exampleuser,ou=users,ou=test,ou=tenants,o=emc");
//		}
//	}
//
//	
//
//}
