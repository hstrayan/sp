package com.pers.smartproxy.representations;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author sathyh2
 * 
 * 
 *         QueryResult class provides a standard Json response to all query
 *         requests
 *
 */
public class QueryResult {

	final Logger logger = LoggerFactory.getLogger(QueryResult.class);

	/**
	 * server name
	 */
	private String serverName;
	/**
	 * Distinguished Name
	 */
	private String dn;
	/**
	 * List of result attrs
	 */
	private List<String> attributes;
	/**
	 * exception message back to client
	 */
	private String exceptionMsg;

	/**
	 * no-args constructor
	 */
	public QueryResult() {
	}

	/**
	 * constructor
	 * 
	 * @param entry
	 * @throws LdapInvalidAttributeValueException
	 */
	public QueryResult(final Entry entry) throws LdapInvalidAttributeValueException {
		prepareJsonResult(entry);
	}

	/**
	 * @return
	 */
	public String getServerName() {
		return serverName;
	}

	/**
	 * @param serverName
	 */
	public void setServerName(String serverName) {
		this.serverName = serverName;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getDn() {
		return dn;
	}

	/**
	 * @param dn
	 */
	@JsonProperty
	public void setDn(String dn) {
		this.dn = dn;
	}

	/**
	 * @return List<String>
	 */
	@JsonProperty
	public List<String> getAttributes() {
		return attributes;
	}

	/**
	 * @param attributes
	 */
	@JsonProperty
	public void setAttributes(List<String> attributes) {
		this.attributes = attributes;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getExceptionMsg() {
		return exceptionMsg;
	}

	/**
	 * @param exceptionMsg
	 */
	@JsonProperty
	public void setExceptionMsg(String exceptionMsg) {
		this.exceptionMsg = exceptionMsg;
	}

	/**
	 * @param entry
	 * @throws LdapInvalidAttributeValueException
	 */
	private void prepareJsonResult(Entry entry) throws LdapInvalidAttributeValueException {
		setDn(entry.getDn().toString());
		Iterator<Attribute> attrIterator = entry.getAttributes().iterator();
		attributes = new ArrayList<String>();
		while (attrIterator.hasNext()) {
			Attribute attr = attrIterator.next();
			if (attr.getString() != null && attr.getString().length() > 0) {
				attributes.add(attr.getString());
			}
		}

	}

}
