package com.pers.smartproxy.handlers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;

/**
 * @author sathyh2
 * 
 *         Signatures for all condition handlers
 *
 */
public interface ConditionHandler {
	/**
	 * @param entry
	 * @return
	 * @throws LdapException
	 */
	public List<Entry> applyCondition(Entry entry) throws LdapException;

	/**
	 * @param dn
	 * @return
	 * @throws LdapException
	 */
	public List<Dn> applyCondition(Dn dn) throws LdapException;

	/**
	 * @param entry
	 * @return
	 */
	public Entry applySearchConditionOnAttributes(Entry entry);

	/**
	 * @param returningAttributesString
	 * @return
	 */
	public String[] applySearchConditionOnAttributes(String[] returningAttributesString);

	/**
	 * @return
	 */
	String applySearchFilterCondition();

	/**
	 * @param mods
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	public List<Modification> getUpdatedMods(Dn dn, Collection<Modification> mods)
			throws IndexOutOfBoundsException, LdapInvalidAttributeValueException;

	/**
	 * @param node
	 */
	public void addNodes(org.apache.directory.api.ldap.model.entry.Entry node);

	/**
	 * @return ArrayList<Entry>
	 */
	public ArrayList<Entry> getNodes();

	/**
	 * @param dn
	 * @param returningAttributesString
	 * @return
	 */
	String[] applySearchConditionOnAttributes(Dn dn, String[] returningAttributesString);

	/**
	 * @param parentDn
	 * @param sourceAttrs
	 * @return
	 * @throws LdapException
	 */
	String[] getMappedAttrs(Dn parentDn, String[] sourceAttrs) throws LdapException;
}
