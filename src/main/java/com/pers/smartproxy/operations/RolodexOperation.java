package com.pers.smartproxy.operations;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;

/**
 * @author sathyh2
 * 
 * Interface for all CRUD operations
 *
 */
/**
 * @author sathyh2
 *
 */
public interface RolodexOperation {
	
	/**
	 * perform operation using entry
	 * @param connection
	 * @param entry
	 * @throws LdapException
	 */
	void performOperation(LdapConnection connection, Entry entry) throws LdapException ;
	
	/**
	 * perform operation using DN
	 * @param connection
	 * @param dn
	 * @throws LdapException
	 */
	void performOperation(LdapConnection connection, Dn dn) throws LdapException ;

	/**
	 * @param connection
	 * @param baseDn
	 * @param filter
	 * @param scope
	 * @param attributes
	 * @return 
	 * @throws LdapException
	 */
	EntryCursor performOperation(LdapConnection connection, Dn baseDn, String filter, SearchScope scope, String[] attributes)
			throws LdapException;

	/**
	 * @param connection
	 * @param baseDn
	 * @param filter
	 * @param scope
	 * @param attributes
	 * @return
	 * @throws LdapException
	 */
	EntryCursor performOperation(LdapConnection connection, String baseDn, String filter, SearchScope scope,
			String[] attributes) throws LdapException;

	/**
	 * @param connection
	 * @param modifyRequest
	 */
	void performOperation(LdapConnection connection, ModifyRequest modifyRequest) throws LdapException;

	void performOperation(LdapConnection connection, Dn dn, boolean cascade) throws CursorException, LdapException;
	
}
