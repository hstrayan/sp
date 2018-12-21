package com.pers.smartproxy.representations;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author sathyh2
 *
 */
public class ProxyConfiguration {

	/**
	 * Dn Mappings
	 */
	private Map<String, String> dnMapping = new ConcurrentHashMap<String, String>();
	
	/**
	 * Object Class Mappings
	 */
	private Map<String, String> objectClasses = new ConcurrentHashMap<String, String>();
	/**
	 * list of attributes mapped
	 */
	private Map<String, String> attributes = new ConcurrentHashMap<String, String>();

	/**
	 * @return Map
	 */
	@JsonProperty
	public Map<String, String> getAttributes() {
		return attributes;
	}

	/**
	 * @param attributes
	 */
	@JsonProperty
	public void setAttributes(Map<String, String> attributes) {
		this.attributes = attributes;
	}

	/**
	 * @return
	 */
	@JsonProperty
	public Map<String, String> getDnMapping() {
		return dnMapping;
	}

	/**
	 * @param dnMapping
	 */
	@JsonProperty
	public void setDnMapping(Map<String, String> dnMapping) {
		this.dnMapping = dnMapping;
	}
	/**
	 * @return  Map<String, String>
	 */
	@JsonProperty
	public Map<String, String> getObjectClasses() {
		return objectClasses;
	}

	/**
	 * @param objectClasses
	 */
	@JsonProperty
	public void setObjectClasses(Map<String, String> objectClasses) {
		this.objectClasses = objectClasses;
	}

}
