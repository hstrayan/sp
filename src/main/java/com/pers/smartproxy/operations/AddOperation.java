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
 * ADD operation
 *
 */
public class AddOperation implements RolodexOperation {
	final Logger logger = LoggerFactory.getLogger(AddOperation.class);

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public void performOperation(LdapConnection connection, Entry entry) throws LdapException {
			connection.add(entry);
	}

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.name.Dn)
	 */
	@Override
	public void performOperation(LdapConnection connection, Dn dn) throws LdapException {
		// TODO Auto-generated method stub
	}

	@Override
	public EntryCursor performOperation(LdapConnection connection, Dn baseDn, String filter, SearchScope scope,
			String[] attributes) throws LdapException {
				return null;
		// TODO Auto-generated method stub
		
	}

	@Override
	public EntryCursor performOperation(LdapConnection connection, String baseDn, String filter, SearchScope scope,
			String[] attributes) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void performOperation(LdapConnection connection, ModifyRequest modifyRequest) {
		logger.info("invoke performOperation");
		
	}

	@Override
	public void performOperation(LdapConnection connection, Dn dn, boolean cascade)
			throws CursorException, LdapException {
		// TODO Auto-generated method stub
		
	}

}
