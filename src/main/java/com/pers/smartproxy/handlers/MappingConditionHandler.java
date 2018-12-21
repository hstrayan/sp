package com.pers.smartproxy.handlers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pers.smartproxy.utils.JsonLdifConvertor;

/**
 * @author sathyh2
 * 
 *         MappingConditionHandler handles all mapping rules around mapped
 *         proxies usecase. This is a class with some complex implementation encapsulating 
 *         custom algorithms and processing rules. Commenting code extensively where required.
 **/
public class MappingConditionHandler implements ConditionHandler {

	final Logger logger = LoggerFactory.getLogger(MappingConditionHandler.class);
	/**
	 * Equals
	 */
	private static final String EQUALS = "=";
	/**
	 * Comma
	 */
	private static final String COMMA = ",";
	/**
	 * Parent DN
	 */
	private static final String PARENTDN = "parentDn";
	/**
	 * Endpoint
	 */
	private static final String ENDPOINT = "endpoint";
	/**
	 * Attribute Map
	 */
	private static final String ATTRMAP = "attrMap";

	/**
	 * list of all registered node for a specific connector
	 */
	private ArrayList<Entry> nodes = null;

	/**
	 * constructor
	 */
	public MappingConditionHandler() {
		nodes = new ArrayList<Entry>();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.conditionhandlers.ConditionHandler#
	 * applyCondition(org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public synchronized List<Entry> applyCondition(final Entry entry) throws LdapException {
		List<Entry> entries = new ArrayList<Entry>();
		Entry updatedEntry = null;
		// get all registered nodes		
		ArrayList<Entry> nodes = getNodes();
		for (Entry node : nodes) {
			// get the parentDn from each iterated node
			Attribute parentDnAttr = node.get(PARENTDN);
			String parentDn = parentDnAttr.getString();
			String incomingDn = entry.getDn().toString().trim();
			// check for match using matching algorithm
			if (checkForMatch(parentDn, incomingDn) == 1 || checkForMatch(parentDn, incomingDn) == 2) {
				logger.info("there is a match");
				// there is a match, so using mapping definitions
				String[] origAttrs = JsonLdifConvertor.splitAttributesByPattern(entry.getDn().toString(), EQUALS);
				Attribute endpoint = node.get(ENDPOINT);
				String dn = null;
				for (Value<?> value : endpoint) {
					dn = value.toString();
					logger.info("dn value is " + dn);
					updatedEntry = new DefaultEntry();
					if (dn.length() > 0) {
						if (checkForMatch(parentDn, incomingDn) == 2) {
							String modifiedDn = getConcatedEntry(incomingDn, parentDn, dn);
							updatedEntry.setDn(new Dn(modifiedDn));
						} else
							updatedEntry.setDn(new Dn(dn));
					}
					if (entry.getAttributes() != null) {
						for (Attribute attribute : entry) {
							String[] compareAttrs = JsonLdifConvertor.splitAttributes(attribute.toString());
							if (!origAttrs[0].trim().equalsIgnoreCase(compareAttrs[0].trim())
									&& !origAttrs[1].trim().equalsIgnoreCase(compareAttrs[0].trim())) {
								updatedEntry.add(attribute);
							}
						}
					}
					logger.info("updatedEntry for dn: " + updatedEntry.getDn().getName());
					entries.add(updatedEntry);
				}
			}
		}
		return entries;
	}

	/**
	 * @param incomingDn
	 * @param dn
	 * @param dn2
	 * @return
	 */
	private String getConcatedEntry(String incomingDn, String parentDn, String dn) {
		String finalDn = incomingDn.substring(0, incomingDn.indexOf(parentDn));
		return finalDn.concat(dn);
	}

	/**
	 * Matching Algorithm
	 * 
	 * @param parentDn
	 * @param incomingDn
	 * @return
	 */
	private int checkForMatch(String parentDn, String incomingDn) {
		if (parentDn.equalsIgnoreCase(incomingDn)) {
			return 1;
		}
		if (incomingDn.contains(parentDn)) {
			return 2;
		}
		return 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.conditionhandlers.ConditionHandler#
	 * applyCondition(org.apache.directory.api.ldap.model.name.Dn)
	 */
	@Override
	public synchronized List<Dn> applyCondition(final Dn dn) throws LdapException {
		List<Dn> dns = new ArrayList<Dn>();
		ArrayList<Entry> nodes = getNodes();
		for (Entry node : nodes) {
			Attribute parentDnAttr = node.get("parentDn");
			String parentDn = parentDnAttr.getString();
			logger.info("parent dn used is " + parentDn);
			if (parentDn.equalsIgnoreCase(dn.getName().trim())) {
				Attribute endpoint = node.get(ENDPOINT);
				String dnIn = null;
				for (Value<?> value : endpoint) {
					dnIn = value.toString();
					dns.add(new Dn(dnIn));
				}
			}
		}
		return dns;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.conditionhandlers.ConditionHandler#
	 * getMappedAttrs(org.apache.directory.api.ldap.model.name.Dn,
	 * java.lang.String[])
	 */
	@Override
	public synchronized String[] getMappedAttrs(final Dn parentDn, String[] sourceAttrs) throws LdapException {
		List<String> attrs = new ArrayList<String>();
		ArrayList<Entry> nodes = getNodes();
		for (Entry node : nodes) {
			if (parentDn.getName().equalsIgnoreCase(node.getDn().getName().trim())) {
				Attribute attrMap = node.get(ATTRMAP);
				String attr = null;
				for (Value<?> value : attrMap) {
					attr = value.toString();
					String[] targetAttrs = attr.split(COMMA);
					for (String sourceAttr : sourceAttrs) {
						for (String arrAttr : targetAttrs) {
							String[] arrAttrArray = arrAttr.split(EQUALS);
							if (sourceAttr.equalsIgnoreCase(arrAttrArray[0])) {
								attrs.add(arrAttrArray[1]);
							}
						}
					}
				}
			}
		}
		return attrs.toArray(new String[attrs.size()]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.conditionhandlers.ConditionHandler#
	 * applySearchConditionOnAttributes(java.lang.String[])
	 */
	@Override
	public synchronized String[] applySearchConditionOnAttributes(final Dn dn,
			final String[] returningAttributesString) {
		List<String> updatedAttrArray = new ArrayList<String>();
		ArrayList<Entry> nodes = getNodes();
		for (Entry node : nodes) {
			String parentDn = node.getDn().toString().trim();
			if (parentDn.equalsIgnoreCase(dn.toString().trim())) {
				String target = null;
				try {
					target = node.get(ATTRMAP).getString().trim();
				} catch (LdapInvalidAttributeValueException e) {
					logger.info(e.getMessage());
				}
				for (String compareString : returningAttributesString) {
					String mappedAttr = getMappingId(target, compareString);
					if (mappedAttr != null && mappedAttr.length() > 0) {
						updatedAttrArray.add(mappedAttr);
					}
				}
			}
		}
		return updatedAttrArray.toArray(new String[updatedAttrArray.size()]);
	}

	/**
	 * @param entry
	 * @return
	 */
	@Override
	public synchronized Entry applySearchConditionOnAttributes(Entry entry) {
		return null;
	}

	/**
	 * Algorithm to retrieve a mapped Id from String of mapped pairs
	 * 
	 * @param target
	 * @param mod
	 * @return
	 */
	protected String getMappingId(String target, String sourceId) throws IndexOutOfBoundsException {
		String[] mappedAttr;
		int index = target.indexOf(sourceId);
		if (index >= 0) {
			String subString = target.substring(index);
			String[] mappedData = subString.split(COMMA);
			mappedAttr = mappedData[0].split(EQUALS);
			if (mappedAttr.length <= 1)
				return mappedAttr[0];
			return mappedAttr[1];
		} else
			return sourceId;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.conditionhandlers.ConditionHandler#
	 * addNodes(org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public void addNodes(Entry node) {
		nodes.add(node);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.conditionhandlers.ConditionHandler#
	 * applySearchFilterCondition()
	 */
	@Override
	public String applySearchFilterCondition() {
		return null;
	}

	/**
	 * @return
	 */
	@Override
	public ArrayList<Entry> getNodes() {
		return nodes;
	}

	/**
	 * @param nodes
	 */
	public void setNodes(ArrayList<Entry> nodes) {
		this.nodes = nodes;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.conditionhandlers.ConditionHandler#
	 * applySearchConditionOnAttributes(java.lang.String[])
	 */
	@Override
	public String[] applySearchConditionOnAttributes(String[] returningAttributesString) {
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.pers.smartproxy.conditionhandlers.ConditionHandler#
	 * getUpdatedMods(org.apache.directory.api.ldap.model.name.Dn,
	 * java.util.Collection)
	 */
	@Override
	public synchronized List<Modification> getUpdatedMods(Dn dn, Collection<Modification> modItems)
			throws IndexOutOfBoundsException, LdapInvalidAttributeValueException {
		// get all the registered nodes
		ArrayList<Entry> nodes = getNodes();
		List<Modification> updatedModItems = new ArrayList<Modification>();
		Modification newMod = null;
		for (Entry node : nodes) {
			// get the parent nodes for the entry and verify against input DN 
			if (node.get(PARENTDN).getString().equalsIgnoreCase(dn.toString())) {
				for (Modification mod : modItems) {
					// retrieve attributes mapping for the given Dn
					String target = node.get(ATTRMAP).getString().trim();
					// use custom algorithm to retrieve the mapped id if
					// applicable
					String mappedAttr = getMappingId(target, mod.getAttribute().getUpId());
					// this part can get a little complex to accomodate all the
					// different operations
					if (mappedAttr != null && mappedAttr.length() > 0) {
						newMod = new DefaultModification(
								ModificationOperation.getOperation(mod.getOperation().getValue()), mappedAttr,
								mod.getAttribute().getString());
						updatedModItems.add(newMod);
					}
				}
			}
		}
		return updatedModItems;
	}

}
