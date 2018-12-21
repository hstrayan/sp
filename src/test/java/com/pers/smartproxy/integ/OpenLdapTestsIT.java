package com.pers.smartproxy.integ;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.stream.IntStream;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.junit.Before;
import org.junit.Test;

/**
 * @author sathyh2
 * 
 *         Integration Tests with Docker containers
 *
 */
public class OpenLdapTestsIT {

	LdapConnection conn = null;
	private static final String HOSTNAME = "192.168.99.100";
	private static final int PORT = 10389;
	private static final String UID = "uid=admin,ou=system";
	private static final String PWD = "secret";

	@Before
	public void setup() throws LdapException {
		conn = new LdapNetworkConnection(HOSTNAME, PORT);
		conn.bind(UID, PWD);
	}

	@Test
	public void testCrudOperations() throws Exception {
		Entry addOpenLdap = new DefaultEntry("ou=deadbolttest,ou=tenants,o=emc", "objectClass: top",
				"objectClass: tenancy", "objectClass: organizationalUnit",
				"resourcesetid: gdfgfd234234234fdf32432", "tenantDomain: deadbolttest","tenantName: deadbolttest","OU: deadbolttest");
		
		Entry ou = new DefaultEntry("ou=users,ou=deadbolttest,ou=tenants,o=emc", "objectClass: top", "objectClass: tenancy",
				"objectClass: organizationalUnit");
		Entry userEntry = new DefaultEntry("uid=exampleuser,ou=users,ou=deadbolttest,ou=tenants,o=emc", "objectClass: top",
				"objectClass: tenancy", "objectClass: organizationalPerson", "objectClass: inetOrgPerson", 
				"tenantId: fd351c6c-a79a-4cb2-a4bc-784273cba4b4", "cn: exampleuser", "sn: lastname", "mail: test@test.com", "tempPwd: test123");
		
		// add tenant
		conn.add(addOpenLdap);
		// add tenant OU
		conn.add(ou);
		// add user
		conn.add(userEntry);
		Entry tenant = conn.lookup("ou=deadbolttest,ou=tenants,o=emc");
		System.out.println(tenant);
		assertNotNull(tenant);
		Entry ouEntry = conn.lookup("ou=users,ou=deadbolttest,ou=tenants,o=emc");
		assertNotNull(ouEntry);
		Entry user = conn.lookup("uid=exampleuser,ou=users,ou=deadbolttest,ou=tenants,o=emc");
		System.out.println(user);
		assertNotNull(user);
		
		
					
		// modify
		ModifyRequest modRequest = new ModifyRequestImpl();
		modRequest.setName(new Dn("uid=exampleuser,ou=users,ou=deadbolttest,ou=tenants,o=emc"));
		Modification mod = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "mail", "test@changed.com");
		modRequest.addModification(mod);
		conn.modify(modRequest);
		Entry modifiedUser = conn.lookup("uid=exampleuser,ou=users,ou=deadbolttest,ou=tenants,o=emc");
		System.out.println("modified user is " +modifiedUser);
		assertNotNull(modifiedUser);
		assertEquals("test@changed.com", modifiedUser.get("mail").getString());
//		// search ALL
		EntryCursor cursor = conn.search("ou=deadbolttest,ou=tenants,o=emc", "(&(objectClass=*))", SearchScope.SUBTREE);
		assertNotNull(cursor);
		while (cursor.next()) {
			assertNotNull(cursor.get());
		}
//		// search user
		EntryCursor object = conn.search("uid=exampleuser,ou=users,ou=deadbolttest,ou=tenants,o=emc", "(&(objectClass=*))",
				SearchScope.OBJECT);
		assertNotNull(object);
		
		//bind
		conn.unBind();
	//	conn.close();
		conn.bind("uid=exampleuser,ou=users,ou=deadbolttest,ou=tenants,o=emc","test123");
		conn.unBind();
	//	conn.close();
	   // negative test
		try{
			conn.bind("uid=exampleuser,ou=users,ou=deadbolttest,ou=tenants,o=emc","tg4Zjr3Ygqh9WVYrIs0");
			conn.unBind();
			conn.close();
		}catch(LdapException e){
			assertNotNull(e);
		}
		
//		//cleanup
//		conn.delete("ou=deadbolttest,ou=tenants,o=emc");
	

		
	}

}
