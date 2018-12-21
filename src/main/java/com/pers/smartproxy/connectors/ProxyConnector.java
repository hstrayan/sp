package com.pers.smartproxy.connectors;

import java.util.List;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;

import com.pers.smartproxy.handlers.ConditionHandler;

/**
 * @author sathyh2
 * 
 *         Proxy Connector interface provides signatures for all CRUD and
 *         Handler operations to be implemented.
 *
 */

/**
 * @author sathyh2
 *
 */
/**
 * @author sathyh2
 *
 */
public interface ProxyConnector {

	/**
	 * perform search on the target ldap schema
	 * 
	 * @return
	 * @throws LdapException
	 * @throws CursorException
	 */
	public EntryCursor searchByDn(final SearchOperationContext searchOperationContext) throws CursorException;

	/**
	 * @param lookupOperationContext
	 * @return
	 * @throws CursorException
	 */
	Entry lookup(final LookupOperationContext lookupOperationContext) throws CursorException;

	/**
	 * search all mapped entries/sub-entries by DN
	 * 
	 * @param attrs
	 * @param searchOperationContext
	 * @return
	 */
	List<EntryCursor> searchMappedDns(final Dn dn, String[] attrs) throws CursorException;

	/**
	 * perform add operation on target ldap schema
	 * 
	 * @param AddOperationContext
	 * @throws LdapException
	 * @throws Exception
	 * 
	 */
	public void add(final AddOperationContext addContext, final boolean isTransparent) throws LdapException;

	/**
	 * @param entry
	 * @param isTransparent
	 * @throws LdapException
	 */
	public void add(final Entry entry, final boolean isTransparent) throws LdapException;

	/**
	 * perform modify operation on target ldap schema
	 * 
	 * @param ModifyOperationContext
	 * @throws LdapException
	 * 
	 */
	public void modify(final ModifyOperationContext modifyContext, String ldapType) throws LdapException;

	

	/**
	 * perform delete operation on target ldap schema
	 * 
	 * @param DeleteOperationContext
	 * @throws LdapException
	 * 
	 */
	public void delete(final DeleteOperationContext deleteContext, final boolean isTransparent) throws LdapException;

	/**
	 * @param cHandler
	 * @throws Exception
	 */
	public void addHandler(final ConditionHandler cHandler);

	/**
	 * @return
	 * @throws Exception
	 */
	public ConditionHandler getConditionHandler();

	/**
	 * @param modifyRequest
	 * @throws LdapException
	 * @throws IndexOutOfBoundsException
	 */
	void modify(ModifyRequest modifyRequest) throws LdapException, IndexOutOfBoundsException;

	/**
	 * @param entry
	 * @param isTransparent
	 * @throws LdapException
	 */
	void addEntry(Entry entry, boolean isTransparent) throws LdapException;

	/**
	 * @param entry
	 * @throws LdapException
	 */
	void addJustEntry(Entry entry) throws LdapException;

	/**
	 * @param dn
	 * @return
	 */
	boolean cascadeDelete(Dn dn);

	/**
	 * @param dn
	 * @return
	 */
	boolean delete(Dn dn);

	/**
	 * @param postMappedDn
	 * @param password
	 * @return
	 */
	boolean authenticate(String postMappedDn, String password);

	/**
	 * @param postMappedDn
	 * @param password
	 * @return
	 */
	Entry authenticateAndGetUser(String postMappedDn, String password);

	/**
	 * @param modifyRequest
	 * @return
	 */
	boolean modifyUser(ModifyRequest modifyRequest);

	/**
	 * @param entry
	 * @return
	 */
	boolean modifyUser(Entry entry);

	/**
	 * @param postMappedDn
	 * @return
	 */
	Entry searchUser(String postMappedDn);

	/**
	 * @param postMappedDn
	 * @param password
	 * @param newPassword
	 * @param isUnicode
	 * @return
	 */
	boolean changePassword(String postMappedDn, String password, String newPassword, boolean isUnicode);

	/**
	 * @param postMappedDn
	 * @param newPassword
	 * @param isUnicode
	 * @return
	 */
	String resetPassword(String postMappedDn, String newPassword, boolean isUnicode);

	/**
	 * @param entry
	 * @throws LdapException
	 */
	void addEntry(Entry entry) throws LdapException;

	/**
	 * @param postMappedDn
	 * @return
	 */
	EntryCursor searchUserLdap(String postMappedDn);

	/**
	 * @param postMappedDn
	 * @param bs
	 * @return
	 * @throws LdapException
	 */
	public void bind(String postMappedDn, byte[] bs) throws LdapException;

	/**
	 * @param searchOperationContext
	 * @return
	 * @throws CursorException
	 */
	EntryCursor searchByUsersDn(SearchOperationContext searchOperationContext) throws CursorException;

	/**
	 * @return LdapConnectionPool
	 */
	public LdapConnectionPool getPool();

	/**
	 * @param dn
	 * @return
	 * @throws CursorException
	 */
	EntryCursor searchByDn(String dn) throws CursorException;

	/**
	 * @param searchContext
	 * @param connector
	 * @return
	 * @throws CursorException
	 */
	public EntryCursor searchByDn(SearchOperationContext searchContext, ProxyConnector connector)
			throws CursorException;

	/**
	 * @param dn
	 * @param conn
	 * @return
	 * @throws CursorException
	 */
	EntryCursor searchByDn(String dn, ProxyConnector conn) throws CursorException;

	Entry searchByUid(SearchOperationContext searchOperationContext) throws CursorException;

}
