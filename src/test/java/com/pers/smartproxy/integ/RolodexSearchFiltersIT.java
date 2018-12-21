package com.pers.smartproxy.integ;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.junit.Before;
import org.junit.Test;

public class RolodexSearchFiltersIT {
	
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
	public void testSearchFilterCriterias() throws Exception {
		
		Entry addtenant = new DefaultEntry(
		        "ou=deadbolt1,ou=tenants,o=emc",
		        "objectClass: top", 
		        "objectClass: tenancy",
		        "objectClass: organizationalUnit",
		        "TENANTID: c44ed784-fb6b-40d4-a770-679c55fad900",
			    "resourcesetid: gdfgfd234234234fdf32432",
			    "tenantDomain: deadbolt1",
			    "tenantName: deadbolt1");
		Entry ou = new DefaultEntry("ou=users,ou=deadbolt1,ou=tenants,o=emc", "objectClass: top", "objectClass: tenancy",
				"objectClass: organizationalUnit");
		Entry userEntry = new DefaultEntry("uid=exampleuser,ou=users,ou=deadbolt1,ou=tenants,o=emc", "objectClass: top",
				"objectClass: tenancy", "objectClass: organizationalPerson", "objectClass: inetOrgPerson", 
				"tenantId: fd351c6c-a79a-4cb2-a4bc-784273cba4b4", "cn: exampleuser", "sn: lastname", "mail: deadbolt.admin@virtustream.com", "tempPwd: tg4Zjr3Ygqh9WVYrIX7");
		
		// add tenant
		conn.add(addtenant);
		// add tenant OU
		conn.add(ou);
		// add user
		conn.add(userEntry);
		
		Entry user = conn.lookup("uid=exampleuser,ou=users,ou=deadbolt1,ou=tenants,o=emc");
		assertNotNull(user);
		
	
        //search filter with objectclass and attributes
		
		EntryCursor cursor = conn.search("ou=deadbolt1,ou=tenants,o=emc", "(&(objectClass=tenancy)(mail=deadboltxzXZX.admin@virtustream.com))", SearchScope.SUBTREE, "*");
		assertNotNull(cursor);
		
		while (cursor.next()){
			Entry entry = cursor.get();
			System.out.println("entry is " + entry);
			assertNotNull(entry);
		}
		 //search filter with attribute only
		EntryCursor cursor2 = conn.search("ou=deadbolt1,ou=tenants,o=emc", "(&(mail=deadbolt.admin@virtustream.com))", SearchScope.SUBTREE, "*");

		while (cursor2.next()){
			Entry entry = cursor2.get();
			assertNotNull(entry);	
		}
//		
//		 //search filter with all objectclasses and attribute 
		EntryCursor cursor3 = conn.search("ou=deadbolt1,OU=tenants,o=emc", "(&(objectClass=*)(mail=deadbolt.admin@virtustream.com))", SearchScope.SUBTREE, "*");
		assertNotNull(cursor3);
		
		while (cursor3.next()){
			Entry entry = cursor3.get();
			System.out.println(entry);
			assertNotNull(entry);	
		}
		
		conn.delete("ou=deadbolt1,oU=tenants,o=emc");
	
				
		
	}
	

}
