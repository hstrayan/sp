package com.pers.smartproxy.integ;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.junit.Before;
import org.junit.Test;

/**
 * @author sathyh2
 * 
 * Validations on Rolodex Attributtes
 *
 */
public class RolodexValidationsIT {
	
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
	public void testDomainValidation() throws Exception {
		Entry addtenant1 = new DefaultEntry(
        "ou=deadboltValid,ou=tenants,o=emc",
        "objectClass: top", 
        "objectClass: tenancy",
        "objectClass: organizationalUnit",
        "TENANTID: c44ed784-fb6b-40d4-a770-679c55fad900",
	    "resourcesetid: gdfgfd234234234fdf32432",
	    "tenantDomain: deadboltValid",
	    "tenantName: deadboltValid");
		Entry ou = new DefaultEntry("ou=users,ou=deadboltValid,ou=tenants,o=emc", "objectClass: top", "objectClass: tenancy",
				"objectClass: organizationalUnit");
		try{
	    //add tenantDomain to match tenant
		conn.add(addtenant1);
		// add ou
		conn.add(ou);
		}catch(LdapException e){
			assertNull(e);
		}
		
		
		Entry addtenant1Invalid = new DefaultEntry(
		        "ou=deadbolt1,ou=tenants,o=emc",
		        "objectClass: top", 
		        "objectClass: tenancy",
		        "objectClass: organizationalUnit",
		        "TENANTID: c44ed784-fb6b-40d4-a770-679c55fad900",
		   	    "resourcesetid: gdfgfd234234234fdf32432",
			    "tenantDomain: invalid",
			    "tenantName: deadbolt1");
		try{
			  //add tenantDomain to not match tenant
		conn.add(addtenant1Invalid);
		}catch(LdapException e){
			assertNotNull(e);
		}
		
		Entry addtenantNoDomain = new DefaultEntry(
		        "ou=deadbolt2,ou=tenants,o=emc",
		        "objectClass: top", 
		        "objectClass: tenancy",
		        "objectClass: organizationalUnit",
			    "resourcesetid: gdfgfd234234234fdf32432",
			    "TENANTID: c44ed784-fb6b-40d4-a770-679c55fad900",
			    "tenantName: deadbolt2"
			   );
				
		try{
		// no tenant domain
		conn.add(addtenantNoDomain);
		}catch(LdapException e){
			assertNotNull(e);
		}
		
		 //cleanup
		conn.delete("ou=deadboltValid,ou=tenants,o=emc");
		
	}
		
	@Test
	public void testValidTenantDn() throws Exception {
		
		Entry addtenant = new DefaultEntry(
		        "ou=deadbolt,ou=xbadtenants,o=emc",
		        "objectClass: top", 
		        "objectClass: tenancy",
		        "objectClass: organizationalUnit",
		        "TENANTID: c44ed784-fb6b-40d4-a770-679c55fad900",
			    "resourcesetid: gdfgfd234234234fdf32432",
			    "tenantDomain: deadbolt",
			    "tenantName: deadbolt");
			try{
			    //Add invalid tenant Dn
				conn.add(addtenant);
				}catch(LdapException e){
					assertNotNull(e);
				}
	}
	
	

}
