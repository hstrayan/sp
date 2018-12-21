package com.pers.smartproxy.integ;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;



import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.junit.Before;
import org.junit.Test;

public class ADTestsIT {
	
	LdapConnection conn = null;
	private static final String HOSTNAME = "192.168.99.100";
	private static final int PORT = 10389;
	private static final String UID = "uid=admin,ou=system";
	private static final String PWD = "secret";
	
	int UF_ACCOUNTENABLE = 0x0001;
	int UF_PASSWD_NOTREQD = 0x0020;
	int UF_NORMAL_ACCOUNT = 0x0200;
	int UF_DONT_EXPIRE_PASSWD = 0x10000;

	@Before
	public void setup() throws LdapException {
		conn = new LdapNetworkConnection(HOSTNAME, PORT);
		conn.bind(UID, PWD);
	}

	@Test
	public void testCrudOperations() throws Exception {
		
		Entry Tenant1 = new DefaultEntry(
		        "ou=Tenant1,OU=tenants,o=emc",
		        "objectClass: top", 
		        "objectClass: tenancy",
		        "objectClass: organizationalUnit",
		        "TENANTID: c44ed784-fb6b-40d4-a770-679c55fad900",
			    "RESOURCESETID: gdfgfd234234234fdf32432",
			    "TENANTDOMAIN: Tenant1",
			    "TENANTNAME: Tenant1",
			    "OU: Tenant1");
				
		Entry Tenant1Ou = new DefaultEntry("ou=users,ou=Tenant1,ou=tenants,o=emc", "objectClass: top", "objectClass: tenancy",
				"objectClass: organizationalUnit");
		Entry user = new DefaultEntry("uid=user,OU=users,ou=Tenant1,ou=tenants,o=emc", "objectClass: top",
				"objectClass: tenancy", "objectClass: organizationalPerson", "objectClass: inetOrgPerson", 
				"tenantId: fd351c6c-a79a-4cb2-a4bc-784273cba4b4", "cn: user", "sn: lastname", "mail: test@virtustream.com", "tempPwd: tg4Zjr3Ygqh9WVYrIX7");
	    //add AD
		conn.add(Tenant1);
		conn.add(Tenant1Ou);
		conn.add(user);
		
		Entry tenant = conn.lookup("oU=Tenant1,ou=tenants,o=emc");
		System.out.println(tenant);
		assertNotNull(tenant);
		Entry ouEntry = conn.lookup("ou=users,ou=Tenant1,ou=tenants,o=emc");
		assertNotNull(ouEntry);
		String distinguishedNameOU = "ou=users,ou=Tenant1,ou=tenants,o=emc";
		assertEquals(ouEntry.get("distinguishedName").getString(),distinguishedNameOU);
		Entry userEntry = conn.lookup("uid=user,ou=users,ou=Tenant1,ou=tenants,o=emc");
		System.out.println(userEntry);
		String distinguishedNameUser = "uid=user,ou=users,ou=Tenant1,ou=tenants,o=emc";
		assertEquals(userEntry.get("distinguishedName").getString(),distinguishedNameUser);
	// search user
	EntryCursor object = conn.search("uid=user,OU=users,OU=Tenant1,OU=tenants,o=emc", "(&(objectClass=*))",
			SearchScope.OBJECT);
	assertNotNull(object);
	// test for case sensitivity and reverse loading tenants
	 Entry deadbolt = conn.lookup("OU=deadbolt,ou=tenants,O=emc");
	 assertNotNull(deadbolt);
	 Entry deadboltOU = conn.lookup("OU=users,OU=deadbolt,ou=tenants,o=emc");
	  assertNotNull(deadboltOU);
	  Entry dbAdmin = conn.lookup("uid=dbadmin,OU=users,OU=deadbolt,ou=tenants,o=emc");
	  assertNotNull(dbAdmin);
	  // uppercase/camelcase 
	  Entry dbAdmin1 = conn.lookup("UID=dbadmin,OU=users,OU=deadbolt,ou=tenants,o=emc");
	  assertNotNull(dbAdmin1);
	  Entry dbAdmin2 = conn.lookup("UiD=dbadmin,Ou=users,OU=deadbolt,ou=tenants,o=emc");
	  assertNotNull(dbAdmin2);
	  
		
	Entry Tenant2 = new DefaultEntry(
	        "ou=Tenant2,ou=tenants,o=emc",
	        "objectClass: top", 
	        "objectClass: tenancy",
	        "objectClass: organizationalUnit",
	        "TENANTID: c44ed784-fb6b-40d4-a770-679c55fad900",
		    "RESOURCESETID: gdfgfd234234234fdf32432",
		    "TENANTDOMAIN: Tenant2",
		    "TENANTNAME: Tenant2",
		    "OU: Tenant2");
				
				Entry ou = new DefaultEntry("ou=users,ou=Tenant2,ou=tenants,o=emc", "objectClass: top", "objectClass: tenancy",
						"objectClass: organizationalUnit");
				Entry userEntry2 = new DefaultEntry("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc", "objectClass: top",
						"objectClass: tenancy", "objectClass: organizationalPerson", "objectClass: inetOrgPerson", 
						"tenantId: fd351c6c-a79a-4cb2-a4bc-784273cba4b4", "cn: user", "sn: lastname", "mail: test@virtustream.com", "tempPwd: tg4Zjr3Ygqh9WVYrIX7");
			    //add AD
				conn.add(Tenant2);
				conn.add(ou);
				conn.add(userEntry2);
				//AD
				Entry adTenantRes2 = conn.lookup("ou=Tenant2,ou=tenants,o=emc");
				System.out.println(adTenantRes2);
				assertNotNull(adTenantRes2);
				Entry adTenantOuRes2 = conn.lookup("ou=users,ou=Tenant2,ou=tenants,o=emc");
				assertNotNull(adTenantOuRes2);
				System.out.println(adTenantOuRes2);
				Entry adUserRes2 = conn.lookup("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc");
				assertNotNull(adUserRes2);
				System.out.println(adUserRes2);
//				//modify AD user
				ModifyRequest modRequest = new ModifyRequestImpl();
				modRequest.setName(new Dn("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc"));
				Modification mod = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "mail", "test@changed.com");
				modRequest.addModification(mod);
				conn.modify(modRequest);
				Entry modifiedUser = conn.lookup("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc");
				System.out.println("modified user is " +modifiedUser);
				assertNotNull(modifiedUser);
				assertEquals("test@changed.com", modifiedUser.get("mail").getString());
								
				// bind AD user	
				conn.bind("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc","tg4Zjr3Ygqh9WVYrIX7");	
			//	 negative bind AD user
				try{
					conn.bind("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc","tg4Zjr3Ygqh9WVYrIXa12");	
				}catch(Exception e){
					assertNotNull(e);
				}
				//change passwd
				    String quotedPassword = "\"" + "tg4Zjr3Ygqh9WVYrIX8" + "\"";
				    char unicodePwd[] = quotedPassword.toCharArray();
				    byte pwdArray[] = new byte[unicodePwd.length * 2];
				    for (int i = 0; i < unicodePwd.length; i++)
				    {
					pwdArray[i * 2 + 1] = (byte) (unicodePwd[i] >>> 8);
					pwdArray[i * 2 + 0] = (byte) (unicodePwd[i] & 0xff);
				    }
				   
			    ModifyRequest modRequest2 = new ModifyRequestImpl();
				modRequest2.setName(new Dn("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc"));
				Modification mod1 = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "userpassword","tg4Zjr3Ygqh9WVYrIX8");
			    modRequest2.addModification(mod1);
				conn.modify(modRequest2);
				//bind
				conn.bind("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc","tg4Zjr3Ygqh9WVYrIX8");
				
				try{
					conn.bind("uid=user,ou=users,ou=Tenant2,ou=tenants,o=emc","tg4Zjr3Ygqh9WVYrIX98");
				}catch(Exception e){
					assertNotNull(e);
				}
//
//				//cleanup: delete tenants in AD
				conn.delete(new Dn("ou=Tenant1,ou=tenants,o=emc"));
				conn.delete(new Dn("ou=Tenant2,ou=tenants,o=emc"));
	
	}
	
	

}
