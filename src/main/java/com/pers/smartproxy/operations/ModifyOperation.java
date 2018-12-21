package com.pers.smartproxy.operations;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author sathyh2
 * 
 * MODIFY operation
 *
 */
public class ModifyOperation implements RolodexOperation {
	final Logger logger = LoggerFactory.getLogger(ModifyOperation.class);

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public void performOperation(LdapConnection connection, Entry entry) throws LdapException {
	}

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.name.Dn)
	 */
	@Override
	public void performOperation(LdapConnection connection, Dn dn) throws LdapException {
		// TODO Auto-generated method stub
	}

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.name.Dn, java.lang.String, org.apache.directory.api.ldap.model.message.SearchScope, java.lang.String[])
	 */
	@Override
	public EntryCursor performOperation(LdapConnection connection, Dn baseDn, String filter, SearchScope scope,
			String[] attributes) throws LdapException {
				return null;
		// TODO Auto-generated method stub
		
	}

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, java.lang.String, java.lang.String, org.apache.directory.api.ldap.model.message.SearchScope, java.lang.String[])
	 */
	@Override
	public EntryCursor performOperation(LdapConnection connection, String baseDn, String filter, SearchScope scope,
			String[] attributes) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.message.ModifyRequest)
	 */
	@Override
	public void performOperation(LdapConnection connection, ModifyRequest modifyRequest) throws LdapException {
		connection.modify(modifyRequest);
		
	}

	@Override
	public void performOperation(LdapConnection connection, Dn dn, boolean cascade)
			throws CursorException, LdapException {
		// TODO Auto-generated method stub
		
	}

}
