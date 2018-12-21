package com.pers.smartproxy.operations;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.OpaqueControl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author sathyh2
 * 
 * DELETE operation
 *
 */
public class DeleteOperation implements RolodexOperation {
	final Logger logger = LoggerFactory.getLogger(DeleteOperation.class);

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public void performOperation(LdapConnection connection, Entry entry) throws LdapException {
			connection.delete(entry.getDn().getName());
	}

	/* (non-Javadoc)
	 * @see com.virtustream.coreservices.rolodex.operations.RolodexOperation#performOperation(org.apache.directory.ldap.client.api.LdapConnection, org.apache.directory.api.ldap.model.name.Dn)
	 */
	@Override
	public void performOperation(LdapConnection connection, Dn dn) throws LdapException {
		connection.delete(dn.getName());
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
		// TODO Auto-generated method stub
		
	}
	
	@Override
	public void performOperation(LdapConnection connection, Dn dn, boolean cascade)
			throws CursorException, LdapException {
		if (connection.isControlSupported("1.2.840.113556.1.4.805")) {
			implementDeleteControl(connection, dn);
		} else {
			cascadingDeleteAlgorithm(connection, dn);
		}
	}

	/**
	 * @param connection
	 * @param dn
	 * @throws LdapException
	 */
	protected void implementDeleteControl(LdapConnection connection, Dn dn) throws LdapException {
		DeleteRequest deleteRequest = new DeleteRequestImpl();
		deleteRequest.setName(dn);
		Control deleteTreeControl = new OpaqueControl("1.2.840.113556.1.4.805");
		deleteRequest.addControl(deleteTreeControl);
		connection.delete(deleteRequest);
	}

	/**
	 * @param connection
	 * @param dn
	 * @throws LdapException
	 * @throws CursorException
	 * @throws LdapInvalidDnException
	 */
	protected void cascadingDeleteAlgorithm(LdapConnection connection, Dn dn)
			throws LdapException, CursorException, LdapInvalidDnException {
		int depth = 0;
		EntryCursor entryCursor = null;
		List<Entry> list = null;
		entryCursor = searchBy(connection, dn, "(objectclass=*)");
		list = new ArrayList<Entry>();
		while (entryCursor.next()) {
			Entry entry = entryCursor.get();
			list.add(entry);
			String[] commas = entry.getDn().toString().split(",");
			if (commas.length > depth) {
				depth = commas.length;
			}
		}
		subTreeDeletes(connection, list, depth);
	}

	/**
	 * @param connection
	 * @param dn
	 * @param conditions
	 * @return
	 * @throws LdapException
	 */
	protected EntryCursor searchBy(LdapConnection connection, Dn dn, String conditions) throws LdapException {
		return connection.search(dn, conditions, SearchScope.SUBTREE);
	}

	/**
	 * @param connection
	 * @param list
	 * @param depth
	 * @throws LdapInvalidDnException
	 * @throws LdapException
	 */
	protected void subTreeDeletes(LdapConnection connection, List<Entry> list, int depth)
			throws LdapInvalidDnException, LdapException {
		Iterator<Entry> entries = list.iterator();
		while (entries.hasNext()) {
			Entry entry = entries.next();
			String[] commas = entry.getDn().toString().split(",");
			if (commas.length == depth) {
				connection.delete(new Dn(entry.getDn().toString()));
			}
		}
		if (depth >= 0) {
			subTreeDeletes(connection, list, depth - 1);
		}
	}
}
