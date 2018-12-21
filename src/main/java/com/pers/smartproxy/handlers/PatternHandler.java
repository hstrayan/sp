package com.pers.smartproxy.handlers;

import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;

/**
 * @author sathyh2
 * 
 *         Regex based Pattern handlers
 *
 */

public class PatternHandler {

	/**
	 * transform part of Dn
	 * 
	 * @param input
	 * @param target
	 * @param regex
	 * @return String
	 */
	public String replaceDnPart(String input, String target, String regex) {
		Pattern p = Pattern.compile(regex);
		Matcher m = p.matcher(input);
		StringBuffer sb = new StringBuffer();
		while (m.find()) {
			m.appendReplacement(sb, target);
		}
		return m.appendTail(sb).toString();
	}

	/**
	 * transform string input
	 * 
	 * @param input
	 * @param target
	 * @param regex
	 * @return String
	 */
	public String replaceDnStr(String input, String target, String regex) {
		Pattern p = Pattern.compile(regex);
		Matcher m = p.matcher(input);
		return m.replaceAll(target);
	}

	/**
	 * Modify Entry
	 * 
	 * @param entry
	 * @param match
	 * @param replacement
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	public Entry modifyEntry(Entry entry, String match, String replacement) throws LdapInvalidAttributeValueException {
		Iterator<Attribute> attrs = entry.getAttributes().iterator();
		while (attrs.hasNext()) {
			Attribute attr = attrs.next();
			if (attr.getUpId().trim().equalsIgnoreCase(match)) {
				attr.setUpId(replacement);
			}
		}
		return entry;
	}

	/**replace first part of DN
	 * 
	 * @param regex
	 * @param baseDn
	 * @param replacement
	 * @return
	 */
	public String replacefirstPartDn(String regex, String baseDn, String replacement) {
		Pattern p = Pattern.compile(regex);
		Matcher m = p.matcher(baseDn);
		return m.replaceFirst(replacement);
	}

	/**
	 * join two different namespaces
	 * 
	 * @param baseDn
	 * @param target
	 * @return
	 */
	public String joinNamespaces(String baseDn, String target) {
		return String.join(",", baseDn, target);
	}

}
