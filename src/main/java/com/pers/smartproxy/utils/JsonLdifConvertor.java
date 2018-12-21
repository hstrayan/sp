package com.pers.smartproxy.utils;

import java.util.regex.Pattern;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;

import com.pers.smartproxy.representations.CrudOperation;

/**
 *
 * 
 * Util class for all Json ApacheDS conversion functionality
 *
 */
/**
 * @author sathyh2
 *
 */
public final class JsonLdifConvertor {

	private static final String ObjectClass = "ObjectClass";
	private static final String COLON = ":";
	private static final String EQUALS = "=";

	/**
	 * private constructor
	 */
	private JsonLdifConvertor() {
	}

	/**
	 * converts Json Representations to
	 * org.apache.directory.api.ldap.model.entry.Entry
	 * 
	 * @param operation
	 * @return Entry
	 * @throws LdapException
	 */
	public static Entry convertJsonToLdifEntry(CrudOperation operation) throws LdapException {
		Entry entry = null;
		if (operation != null) {
			entry = new DefaultEntry();
			entry.setDn(new Dn(operation.getDn()));
			Attribute objectClasses = new DefaultAttribute(ObjectClass);
			if (operation.getObjectClass() != null) {
				for (String s : operation.getObjectClass()) {
					objectClasses.add(s);
				}
				entry.add(objectClasses);
			}
			if (operation.getAttributes() != null) {
				for (String s : operation.getAttributes()) {
					String[] splitAttribute = s.split(Pattern.quote(COLON));
					Attribute attribute = new DefaultAttribute(splitAttribute[0].trim());
					attribute.add(splitAttribute[1].trim());
					entry.add(attribute);
				}
			}
		}
		return entry;
	}

	/**
	 * @param attribute
	 * @return
	 */
	public static String[] splitAttributes(String attribute) {
		return attribute.split(Pattern.quote(COLON));
	}

	/**
	 * @param attribute
	 * @return
	 */
	public static String[] splitAttributesByPattern(String attribute, String pattern) {
		return attribute.split(Pattern.quote(pattern));
	}
	
	
	/**
	 * @param dn
	 * @return
	 */
	public static String getDnFirstPart(String dn){
		String dns[] = dn.split(EQUALS);
		return dns[1];
	}
}
