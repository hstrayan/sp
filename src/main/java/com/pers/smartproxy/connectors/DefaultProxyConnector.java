package com.pers.smartproxy.connectors;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import com.pers.smartproxy.representations.ConnectorInfo;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.EntryCursorImpl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.server.core.api.interceptor.context.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pers.smartproxy.handlers.ConditionHandler;
import com.pers.smartproxy.operations.AddOperation;
import com.pers.smartproxy.operations.DeleteOperation;
import com.pers.smartproxy.operations.ModifyOperation;
import com.pers.smartproxy.utils.LdapCrudUtils;

/**
 * @author sathyh2
 * 
 *         DefaultProxyConnector extends the BaseProxyconnector to implment all
 *         CRUD operations against configured datasources.
 *
 */


public class DefaultProxyConnector extends BaseProxyConnector implements ProxyConnector {

	final Logger logger = LoggerFactory.getLogger(DefaultProxyConnector.class);

	/**
	 * condition handlers
	 */
	private ConditionHandler cHandler = null;

	/**
	 * objectclass used for search by default
	 */
	private static String DEFAULTOBJCLS = "(objectClass=*)";

	int UF_ACCOUNTENABLE = 0x0001;
	int UF_PASSWD_NOTREQD = 0x0020;
	int UF_PASSWD_CANT_CHANGE = 0x0040;
	int UF_NORMAL_ACCOUNT = 0x0200;
	int UF_DONT_EXPIRE_PASSWD = 0x10000;
	/**
	 * no-args contructor
	 */
	public DefaultProxyConnector() {
		super();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.pers.smartproxy.connectors.ProxyConnector#
	 * searchMappedDns(org.apache.directory.api.ldap.model.name.Dn,
	 * java.lang.String[])
	 */
	@Override
	public List<EntryCursor> searchMappedDns(final Dn dn, final String[] attrs) throws CursorException {
		EntryCursor cursor = null;
		List<Dn> dns = null;
		LdapConnection connection = null;
		List<EntryCursor> cursors = new ArrayList<EntryCursor>();
		try {
			connection = getPool().getConnection();
			dns = getUpdatedDn(dn);
			if (dns != null) {
				searchAndLoadCursor(dn, attrs, dns, connection, cursors);
			}
		} catch (LdapException e) {
			logger.info("Search Error: " + e.getMessage());
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info(e.getMessage());
			}
		}
		return cursors;
	}

	/**
	 * @param connectorConfig
	 * @param connectorOperations
	 * @throws LdapException
	 */
	public DefaultProxyConnector(final ConnectorInfo connectorInfo) throws LdapException {
		super(connectorInfo);
	}

	/**
	 * @param dn
	 * @param attrs
	 * @param dns
	 * @param connection
	 * @param cursors
	 * @throws LdapException
	 */
	protected void searchAndLoadCursor(Dn dn, String[] attrs, List<Dn> dns, LdapConnection connection,
			List<EntryCursor> cursors) throws LdapException {
		EntryCursor cursor;
		for (Dn mappedDn : dns) {
			// get all entries/sub-entries
			if (attrs.length > 0) {
				// replace with mapped fields
				cHandler = getConditionHandler();
				String[] mappedAttrs = cHandler.getMappedAttrs(dn, attrs);
				cursor = connection.search(mappedDn, DEFAULTOBJCLS, SearchScope.SUBTREE, mappedAttrs);
			} else {
				cursor = connection.search(mappedDn, DEFAULTOBJCLS, SearchScope.SUBTREE, "*");
			}
			cursors.add(cursor);
		}
	}

	
	
	@Override
	public EntryCursor searchByDn(final SearchOperationContext searchOperationContext) throws CursorException {
		EntryCursor cursor = null;
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			if (connection != null) {
				String filtered = LdapCrudUtils.truncFilter( searchOperationContext.getFilter().toString());
				cursor = connection.search(searchOperationContext.getDn(),
						filtered, searchOperationContext.getScope(), "*");
			}
			
		} catch (LdapException e) {
			logger.info("Search Error: " + e.getMessage());
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info(e.getMessage());
			}
		}
		return cursor;
	}
	@Override
	public EntryCursor searchByUsersDn(final SearchOperationContext searchOperationContext) throws CursorException {
		EntryCursor cursor = null;
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			if (connection != null) {
				System.out.println("DN  is " + searchOperationContext.getDn());
				cursor = connection.search(searchOperationContext.getDn(), "(objectclass=*)", SearchScope.OBJECT);
			}
			
		} catch (LdapException e) {
			logger.info("Search Error: " + e.getMessage());
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info(e.getMessage());
			}
		}
		return cursor;
	}

	@Override
	public Entry lookup(final LookupOperationContext lookupOperationContext) throws CursorException {
		Entry entry = null;
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			if (connection != null) {
				entry = connection.lookup(lookupOperationContext.getDn());
			}
		} catch (LdapException e) {
			logger.info("Search Error: " + e.getMessage());
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info(e.getMessage());
			}
		}
		return entry;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#add(org.
	 * apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public void add(final AddOperationContext addContext, final boolean isTransparentProxy) throws LdapException {
		logger.info("transparent proxy is " + isTransparentProxy);
		List<Entry> entries = null;
		LdapConnection connection = getPool().getConnection();
		AddOperation add = new AddOperation();
		if (isTransparentProxy) {
			add.performOperation(connection, addContext.getEntry());
		} else {
			entries = getUpdatedEntry(addContext.getEntry());
			if (entries != null) {
				iterateEntriesAndAdd(entries, connection, add);
			}
		}
		try {
			getPool().releaseConnection(connection);
		} catch (LdapException e) {
			logger.info(e.getMessage());
		}
	}

	protected void iterateEntriesAndAdd2(List<Entry> entries, LdapConnection connection, AddOperation add)
			throws LdapException {
		Iterator<Entry> iterEntry = entries.iterator();
		while (iterEntry.hasNext()) {
			add.performOperation(connection, iterEntry.next());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#add(org.
	 * apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public void modify(final ModifyOperationContext modifyContext, String ldapType)
			throws LdapException, IndexOutOfBoundsException {

		LdapConnection connection = getPool().getConnection();
		ModifyRequest modRequest2 = null;
			if (connection != null) {
				if (ldapType.equalsIgnoreCase("AD")){
					List<Modification> mods = modifyContext.getModItems();
					for(Modification mod:mods){
						// add camelcase
						if (mod.getAttribute().getId().equalsIgnoreCase("userpassword") || mod.getAttribute().getId().equalsIgnoreCase("userPassword") ){
							     modRequest2 = new ModifyRequestImpl();
								modRequest2.setName(modifyContext.getDn());
								 String userPwdBytes = new String(mod.getAttribute().getBytes());
							     String quotedPassword = "\"" +   userPwdBytes + "\"";
								    char unicodePwd[] = quotedPassword.toCharArray();
								    byte pwdArray[] = new byte[unicodePwd.length * 2];
								    for (int i = 0; i < unicodePwd.length; i++)
								    {
									pwdArray[i * 2 + 1] = (byte) (unicodePwd[i] >>> 8);
									pwdArray[i * 2 + 0] = (byte) (unicodePwd[i] & 0xff);
								    }
								Modification mod1 = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "UnicodePwd",pwdArray);
								Modification mod2 = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,"userAccountControl" ,Integer.toString(UF_NORMAL_ACCOUNT + UF_DONT_EXPIRE_PASSWD));
								modRequest2.addModification(mod1);
								modRequest2.addModification(mod2);
						}
					}	
					
				}
					
				if (modRequest2 != null){
					// change pwd in AD	
					connection.modify(modRequest2);
				} else{				
				performModify(modifyContext.getDn(), modifyContext.getModItems(), connection);
				}
			}
		
		try {
			getPool().releaseConnection(connection);
		} catch (LdapException e) {
			logger.info(e.getMessage());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#modify(org
	 * .apache.directory.api.ldap.model.message.ModifyRequest)
	 */
	@Override
	public void modify(final ModifyRequest modifyRequest) throws LdapException, IndexOutOfBoundsException {
		// Dn updatedDn = null;
		List<Dn> dns = null;
		List<Modification> updatedMods = null;
		LdapConnection connection = getPool().getConnection();
		dns = getUpdatedDn(modifyRequest.getName());
		if (dns != null && !dns.isEmpty()) {
			logger.info("inside the dns not empty");
			updateAndPropagateModify(modifyRequest, dns, connection);
		} else {
			logger.info("non-mapping modify");
			if (connection != null) {
				performModify(modifyRequest.getName(), modifyRequest.getModifications(), connection);
			}
		}
		try {
			getPool().releaseConnection(connection);
		} catch (LdapException e) {
			logger.info(e.getMessage());
		}
	}
	
	

	/**
	 * @param modifyRequest
	 * @param dns
	 * @param connection
	 * @throws LdapInvalidAttributeValueException
	 * @throws LdapException
	 */
	protected void updateAndPropagateModify(final ModifyRequest modifyRequest, List<Dn> dns, LdapConnection connection)
			throws LdapInvalidAttributeValueException, LdapException {
		List<Modification> updatedMods;
		updatedMods = getUpdatedMods(modifyRequest.getName(), modifyRequest.getModifications());
		logger.info("updatedmods size is : " + updatedMods.size());
		propagateModify(dns, updatedMods, connection);
	}

	/**
	 * @param dn
	 * @param mods
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	protected List<Modification> getUpdatedMods(Dn dn, Collection<Modification> mods)
			throws IndexOutOfBoundsException, LdapInvalidAttributeValueException {
		return getConditionHandler().getUpdatedMods(dn, mods);
	}

	/**
	 * @param updatedDn
	 * @param updatedMods
	 * @param connection
	 * @throws LdapException
	 */
	protected void performModify2(Dn updatedDn, Collection<Modification> updatedMods, LdapConnection connection)
			throws LdapException {
		ModifyRequest modifyRequest = new ModifyRequestImpl();
		modifyRequest.setName(updatedDn);
		for (Modification mod : updatedMods) {
			modifyRequest.addModification(mod);
		}
		modify(connection, modifyRequest);
	}

	/**
	 * @param connection
	 * @param modifyRequest
	 * @throws LdapException
	 */
	protected void modify2(LdapConnection connection, ModifyRequest modifyRequest) throws LdapException {
		ModifyOperation modify = new ModifyOperation();
		modify.performOperation(connection, modifyRequest);
	}

	/**
	 * @param dns
	 * @param updatedMods
	 * @param connection
	 * @throws LdapException
	 */
	protected void propagateModify2(List<Dn> dns, List<Modification> updatedMods, LdapConnection connection)
			throws LdapException {
		ModifyRequest modifyRequest = null;
		for (Dn dn : dns) {
			modifyRequest = new ModifyRequestImpl();
			modifyRequest.setName(dn);
			for (Modification mod : updatedMods) {
				modifyRequest.addModification(mod);
			}
			modify(connection, modifyRequest);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#delete(org
	 * .apache.directory.server.core.api.interceptor.context.
	 * DeleteOperationContext)
	 */
	@Override
	public void delete(final DeleteOperationContext deleteContext, final boolean isTransparentProxy)
			throws LdapException {
		List<Dn> dns = null;
		LdapConnection connection = getPool().getConnection();
		DeleteOperation delete = new DeleteOperation();
		dns = getUpdatedDn(deleteContext.getDn());
		if (dns != null && !dns.isEmpty()) {
			performMultipleDeletes(dns, connection, delete);
		} else {
			if (connection != null) {
				delete.performOperation(connection, deleteContext.getDn());
			}
		}
		try {
			getPool().releaseConnection(connection);
		} catch (LdapException e) {
			logger.info(e.getMessage());
		}
	}

	/**
	 * @param dns
	 * @param connection
	 * @param delete
	 * @throws LdapException
	 */
	protected void performMultipleDeletes2(List<Dn> dns, LdapConnection connection, DeleteOperation delete)
			throws LdapException {
		for (Dn dn : dns) {
			delete.performOperation(connection, dn);
		}
	}

	/**
	 * @param dn
	 * @return
	 */
	protected List<Dn> getUpdatedDn(Dn dn) {
		List<Dn> updatedDn = null;
		ConditionHandler cHandler = null;
		cHandler = getConditionHandler();
		if (cHandler != null) {
			try {
				updatedDn = cHandler.applyCondition(dn);
			} catch (LdapException e) {
				logger.info(e.getMessage());
			}
			logger.info("dn is " + updatedDn.toString());
		}
		return updatedDn;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#addHandler
	 * (com.pers.smartproxy.conditionhandlers.ConditionHandler)
	 */
	@Override
	public void addHandler(final ConditionHandler cHandler) {
		this.cHandler = cHandler;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.pers.smartproxy.connectors.ProxyConnector#
	 * getConditionHandler()
	 */
	@Override
	public ConditionHandler getConditionHandler() {
		return cHandler;
	}

	/**
	 * @param addContext
	 * @return
	 * @throws LdapInvalidDnException
	 * @throws LdapException
	 */
	protected List<Entry> getUpdatedEntry(final Entry entry) throws LdapException {
		logger.info("applying conditions");
		List<Entry> updatedEntry = null;
		ConditionHandler cHandler = null;
		cHandler = getConditionHandler();
		if (cHandler != null) {
			updatedEntry = cHandler.applyCondition(entry);
			logger.info("updated Entry size is: " + updatedEntry.size());
		}
		return updatedEntry;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#add(org.
	 * apache.directory.api.ldap.model.entry.Entry, boolean)
	 */
	@Override
	public void addEntry(Entry entry, boolean isTransparent) throws LdapException {
		List<Entry> entries = null;
		LdapConnection connection = getPool().getConnection();
		AddOperation add = new AddOperation();
		entries = getUpdatedEntry(entry);
		if (entries != null && !entries.isEmpty()) {
			addMultipleEntries(entries, connection, add);
		} else {
			if (connection != null) {
				add.performOperation(connection, entry);
			}
		}
		try {
			getPool().releaseConnection(connection);
		} catch (LdapException e) {
			logger.info(e.getMessage());
		}
	}

	/**
	 * @param entries
	 * @param connection
	 * @param add
	 * @throws LdapException
	 */
	protected void addMultipleEntries2(List<Entry> entries, LdapConnection connection, AddOperation add)
			throws LdapException {
		logger.info("entries size is " + entries.size());
		iterateEntriesAndAdd(entries, connection, add);
	}

	// new

	/**
	 * @param entries
	 * @param connection
	 * @param add
	 * @throws LdapException
	 */
	protected void iterateEntriesAndAdd(List<Entry> entries, LdapConnection connection, AddOperation add)
			throws LdapException {
		Iterator<Entry> iterEntry = entries.iterator();
		while (iterEntry.hasNext()) {
			add.performOperation(connection, iterEntry.next());
		}
	}

	/**
	 * @param updatedDn
	 * @param updatedMods
	 * @param connection
	 * @throws LdapException
	 */
	protected void performModify(Dn updatedDn, Collection<Modification> updatedMods, LdapConnection connection)
			throws LdapException {
		ModifyRequest modifyRequest = new ModifyRequestImpl();
		modifyRequest.setName(updatedDn);
		for (Modification mod : updatedMods) {
			modifyRequest.addModification(mod);
		}
		modify(connection, modifyRequest);
	}

	/**
	 * @param connection
	 * @param modifyRequest
	 * @throws LdapException
	 */
	protected void modify(LdapConnection connection, ModifyRequest modifyRequest) throws LdapException {
		ModifyOperation modify = new ModifyOperation();
		modify.performOperation(connection, modifyRequest);
	}

	/**
	 * @param dns
	 * @param updatedMods
	 * @param connection
	 * @throws LdapException
	 */
	protected void propagateModify(List<Dn> dns, List<Modification> updatedMods, LdapConnection connection)
			throws LdapException {
		ModifyRequest modifyRequest = null;
		for (Dn dn : dns) {
			modifyRequest = new ModifyRequestImpl();
			modifyRequest.setName(dn);
			for (Modification mod : updatedMods) {
					modifyRequest.addModification(mod);
			}
			modify(connection, modifyRequest);
		}
	}

	/**
	 * @param dns
	 * @param connection
	 * @param delete
	 * @throws LdapException
	 */
	protected void performMultipleDeletes(List<Dn> dns, LdapConnection connection, DeleteOperation delete)
			throws LdapException {
		for (Dn dn : dns) {
			delete.performOperation(connection, dn);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#add(org.
	 * apache.directory.api.ldap.model.entry.Entry, boolean)
	 */
	@Override
	public synchronized void add(Entry entry, boolean isTransparent) throws LdapException {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			// AddOperation add = new AddOperation();
			if (connection != null) {
				connection.add(entry);
				// add.performOperation(connection, entry);
			}
		} finally {
			getPool().releaseConnection(connection);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#add(org.
	 * apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public synchronized void addEntry(Entry entry) throws LdapException {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			
			if (connection != null) {
				if (entry.containsAttribute("unicodepassword")) {
					String passwd = entry.get("unicodePassword").getString();
					entry.removeAttributes("unicodepassword");
					Attribute userAccountControl = new DefaultAttribute("userAccountControl");
					userAccountControl.add(Integer.toString(
							UF_NORMAL_ACCOUNT + UF_PASSWD_NOTREQD + UF_DONT_EXPIRE_PASSWD + UF_ACCOUNTENABLE));
					entry.add(userAccountControl);
					connection.add(entry);
					String quotedPassword = "\"" + passwd + "\"";

					char unicodePwd[] = quotedPassword.toCharArray();
					byte pwdArray[] = new byte[unicodePwd.length * 2];
					for (int i = 0; i < unicodePwd.length; i++) {
						pwdArray[i * 2 + 1] = (byte) (unicodePwd[i] >>> 8);
						pwdArray[i * 2 + 0] = (byte) (unicodePwd[i] & 0xff);
					}
					ModifyRequest modRequest = new ModifyRequestImpl();
					modRequest.setName(entry.getDn());
					Modification mod = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "UnicodePwd",
							pwdArray);

					Modification mod1 = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
							"userAccountControl", Integer.toString(UF_NORMAL_ACCOUNT + UF_DONT_EXPIRE_PASSWD));
					modRequest.addModification(mod);
					modRequest.addModification(mod1);

					connection.modify(modRequest);
						
					
				} else
				connection.add(entry);
				
			}
		} finally {
			getPool().releaseConnection(connection);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.pers.smartproxy.connectors.ProxyConnector#
	 * cascadeDelete(org.apache.directory.api.ldap.model.name.Dn)
	 */
	@Override
	public synchronized boolean cascadeDelete(final Dn dn) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			DeleteOperation delete = new DeleteOperation();
			if (connection != null) {
				try {
					delete.performOperation(connection, dn, true);
				} catch (CursorException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
		return true;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#delete(org
	 * .apache.directory.api.ldap.model.name.Dn)
	 */
	@Override
	public synchronized boolean delete(final Dn dn) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
		//	DeleteOperation delete = new DeleteOperation();
			if (connection != null) {
				connection.delete(dn);
			}
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
		return true;
	}

	/**
	 * @param entries
	 * @param connection
	 * @param add
	 * @throws LdapException
	 */
	protected void addMultipleEntries(List<Entry> entries, LdapConnection connection, AddOperation add)
			throws LdapException {
		logger.info("entries size is " + entries.size());
		iterateEntriesAndAdd(entries, connection, add);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.pers.smartproxy.connectors.ProxyConnector#
	 * authenticate(java.lang.String, java.lang.String)
	 */
	@Override
	public synchronized boolean authenticate(String postMappedDn, String password) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			connection.bind(postMappedDn, password);
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return false;
		}
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#lookupUser
	 * (java.lang.String)
	 */
	@Override
	public synchronized Entry authenticateAndGetUser(String postMappedDn, String password) {
		LdapConnection connection = null;
		Entry entry = null;
		try {
			connection = getPool().getConnection();
			entry = connection.lookup(postMappedDn);
			if (entry != null) {
				connection.bind(postMappedDn, password);
			}
		} catch (Exception e) {
			logger.info("LdapException:" + e);
			return null;
		} finally {
			try {
				connection.unBind();
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
		return entry;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#modifyUser
	 * (org.apache.directory.api.ldap.model.message.ModifyRequest)
	 */
	@Override
	public synchronized boolean modifyUser(ModifyRequest modifyRequest) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			if (modifyRequest != null)
				connection.modify(modifyRequest);
		} catch (Exception e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#modifyUser
	 * (org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public synchronized boolean modifyUser(Entry entry) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			if (entry != null)
				connection.modify(entry, ModificationOperation.REPLACE_ATTRIBUTE);
		} catch (Exception e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.connectors.ProxyConnector#searchUser
	 * (java.lang.String)
	 */
	@Override
	public synchronized Entry searchUser(String postMappedDn) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			EntryCursor cursor = connection.search(postMappedDn, "(objectclass=*)", SearchScope.SUBTREE);
			if (cursor.next()) {
				return cursor.get();
			}
		} catch (Exception e) {
			logger.info("LdapException:" + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
		return null;
	}

	@Override
	public synchronized EntryCursor searchUserLdap(String postMappedDn) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			SearchRequest request = new SearchRequestImpl();
			request.setBase(new Dn(postMappedDn));
			request.setFilter("(objectclass=*)");
			request.setScope(SearchScope.SUBTREE);
			SearchCursor cursor = connection.search(request);
			EntryCursor entries = new EntryCursorImpl(cursor);
			return entries;
		} catch (Exception e) {
			logger.info("LdapException:" + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
	}

	@Override
	public synchronized boolean changePassword(String postMappedDn, String password, String newPassword,
			boolean isUnicode) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			Entry userEntry = authenticateAndGetUser(postMappedDn, password);
			if (userEntry != null) {
				modifyByLdapType(postMappedDn, newPassword, isUnicode, connection);
			} else
				return false;
		} catch (Exception e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.pers.smartproxy.connectors.ProxyConnector#
	 * resetPassword(java.lang.String, java.lang.String, boolean)
	 */
	@Override
	public synchronized String resetPassword(String postMappedDn, String newPassword, boolean isUnicode) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			modifyByLdapType(postMappedDn, newPassword, isUnicode, connection);
		} catch (Exception e) {
			logger.info("LdapException:" + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
		return newPassword;
	}

	/**
	 * @param postMappedDn
	 * @param newPassword
	 * @param isUnicode
	 * @param connection
	 * @throws LdapException
	 */
	protected void modifyByLdapType(String postMappedDn, String newPassword, boolean isUnicode,
			LdapConnection connection) throws LdapException {
		if (isUnicode) {
			connection.modify(postMappedDn, new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
					"unicodePwd", LdapCrudUtils.generateSSHA(newPassword)));
		} else
			connection.modify(postMappedDn, new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
					"userPassword", LdapCrudUtils.generateSSHA(newPassword)));
	}

	@Override
	public void addJustEntry(Entry entry) throws LdapException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see com.pers.smartproxy.connectors.ProxyConnector#bind(java.lang.String, byte[])
	 */
	@Override
	public void bind(String postMappedDn, byte[] password) throws LdapException {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			connection.bind(postMappedDn, new String(password, StandardCharsets.UTF_8));
		} finally {
			try {
				getPool().releaseConnection(connection);		
				connection.unBind();
				} catch (LdapException e) {
				logger.info("LdapException:" + e);
			}
		}
	}

	

	/**
	 * @param mod
	 * @param splitStr
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	private Modification creatMod(Modification mod, String splitStr) throws LdapInvalidAttributeValueException {
		Modification newMod;
		String[] srcAttr = splitStr.split("=");
		int operation = mod.getOperation().getValue();
		newMod = new DefaultModification(ModificationOperation.getOperation(operation),
				srcAttr[1], mod.getAttribute().getString());
		return newMod;
	}

	@Override
	public EntryCursor searchByDn(String dn) throws CursorException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public EntryCursor searchByDn(SearchOperationContext searchContext, ProxyConnector connector)
			throws CursorException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public EntryCursor searchByDn(String dn, ProxyConnector conn) throws CursorException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry searchByUid(SearchOperationContext searchOperationContext) throws CursorException {
		// TODO Auto-generated method stub
		return null;
	}
}
