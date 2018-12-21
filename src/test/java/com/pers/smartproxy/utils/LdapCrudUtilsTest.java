package com.pers.smartproxy.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.junit.Test;

public class LdapCrudUtilsTest {
	
	@Test
	public void testGetUserNameFromDn() {
		String dnName = "uid=user1,ou=users,ou=tenant1,ou=tenants,o=emc";
		String tenantName = LdapCrudUtils.getUserNameFromDn(dnName);
		assertEquals(tenantName,"user1");
	}
	
	@Test
	public void testGetTenantNameFromDn() {
		String dnName = "ou=tenant1,ou=tenants,o=emc";
		String tenantName = LdapCrudUtils.getTenantNameFromDn(dnName);
		assertEquals(tenantName,"tenant1");
	}
	@Test
	public void testgetTenantDnFromUserDn() {
		String dnName = "uid=user1,ou=users,ou=tenant1,ou=tenants,o=emc";
		String tenantDn= LdapCrudUtils.getTenantDnFromUserDn(dnName);
		assertEquals(tenantDn,"ou=tenant1,ou=tenants,o=emc");
	}
	
	@Test
	public void testTruncFilter() {
		String filter = "(&(objectClass=tenancy)(mail=test@virtustream.com))";
		assertEquals(LdapCrudUtils.truncFilter(filter),"(&(objectClass=inetOrgPerson)(mail=test@virtustream.com))");
			
	}
	@Test
	public void testgenerateSSHA() {
		String pwd = "stpassword";
		String sshPwd = LdapCrudUtils.generateSSHA(pwd);
		assertNotNull(sshPwd);
	}
	@Test
	public void testCreateDnForTranslation() {
		String userName = "user1";
		String sourceUserNode = "ou=users,ou=tenants,o=emc";
		String mappings = "";
		String dn = LdapCrudUtils.createDnForTranslation(userName,sourceUserNode,mappings);
		assertNotNull(dn);
		assertEquals(dn,"uid=user1,ou=users,ou=tenants,o=emc");
	}
	@Test
	public void testGetFirstPartDn() {
		String dnName = "ou=tenants,o=emc";
		String dn= LdapCrudUtils.getFirstPartDn(dnName);
		assertEquals(dn,"ou=tenants");
	}
	@Test
	public void testgetTenantFromDn() {
		String dnName = "ou=testtenant,ou=tenants,o=emc";
		String dn= LdapCrudUtils.getTenantFromDn(dnName);
		assertEquals(dn,"ou=testtenant,ou=tenants,o=emc");
	}
	@Test
    public  void replaceWithRolodexDn() throws LdapException{
		
		String roldoexDn = LdapCrudUtils.getRolodexDn("CN=user,OU=users,OU=Tenant2,OU=Rolodex,OU=Customers,OU=xstream,DC=namerica,DC=ef86,DC=net");
		String newdn = roldoexDn.replace("CN", "uid");
		System.out.println(newdn);
	}
	
	@Test
	public void isValidTenant() throws LdapException{
		
		String dn = "ou=tenant,ou=notvalid,o=emc";
		assertFalse(LdapCrudUtils.isValidTenantStruct(dn));
		
	}

}
