package com.pers.smartproxy.operations;

import java.io.IOException;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author sathyh2
 * 
 * ADD operation
 *
 */
public class QueryOperation implements RolodexOperation {
	final Logger logger = LoggerFactory.getLogger(QueryOperation.class);

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public EntryCursor performOperation(LdapConnection connection, String mappedDn, String filter, SearchScope scope, String[] attributes) throws LdapException {
		EntryCursor cursor = null;
		LdapConnection conn = new LdapNetworkConnection("ldap",389);
		try {
			conn.bind("cn=admin,dc=deadbolt,dc=emc","Password1");
			 cursor = conn.search(mappedDn,"(objectClass=*)",
					SearchScope.ONELEVEL);
			 if(cursor.next()){
				 System.out.println("cursor is " + cursor.get());
			 }
		} catch (LdapException | CursorException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			conn.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cursor;
	}

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.name.Dn)
	 */
	@Override
	public void performOperation(LdapConnection connection, Dn dn) throws LdapException {
		// TODO Auto-generated method stub
	}

	@Override
	public void performOperation(LdapConnection connection, Entry entry) throws LdapException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public EntryCursor performOperation(LdapConnection connection, Dn baseDn, String filter, SearchScope scope,
			String[] attributes) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void performOperation(LdapConnection connection, ModifyRequest modifyRequest) {
		// TODO Auto-generated method stub
		
	}



	@Override
	public void performOperation(LdapConnection connection, Dn dn, boolean cascade)
			throws CursorException, LdapException {
		// TODO Auto-generated method stub
		
	}

}
