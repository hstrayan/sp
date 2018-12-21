package com.pers.smartproxy.representations;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author sathyh2
 * 
 * Tenancy Object to deserialize json POST request
 *
 */
public class Tenancy {
	
	/**
	 *  tenant name
	 */
	private String tenantName;
	
	/**
	 *  tenant Id
	 */
	
	private String tenantId;
	/**
	 * tenant location at source ldap
	 */
	@NotNull
	private String sourceTenantDn;
	
	/**
	 * users lcoation at source ldap
	 */
	@NotNull
	private String sourceUsersDn;
	
	/**
	 * connection string - colon delimited
	 */
	@NotNull
	private String connectionString;
	
	/**
	 * attrs mapping, comma delimited
	 */
	private String attrsMap;
	
	/**
	 * readonly - is source ldap read only?
	 */
	@NotNull
	private boolean readOnly;
	/**
	 * ldapType - AD or other directory servers (defined from UI)
	 */
	@NotNull
	private String ldapType;
	
	@NotNull
	private String resourceSetID;
	
	/**
	 * @return String
	 */
	@JsonProperty
	public String getTenantName() {
		return tenantName;
	}

	/**
	 * @param tenantName
	 */
	@JsonProperty
	public void setTenantName(String tenantName) {
		this.tenantName = tenantName;
	}
	/**
	 * @return
	 */
	@JsonProperty
	public String getTenantId() {
		return tenantId;
	}

	/**
	 * @param tenantId
	 */
	@JsonProperty
	public void setTenantId(String tenantId) {
		this.tenantId = tenantId;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getSourceTenantDn() {
		return sourceTenantDn;
	}

	/**
	 * @param sourceTenantDn
	 */
	@JsonProperty
	public void setSourceTenantDn(String sourceTenantDn) {
		this.sourceTenantDn = sourceTenantDn;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getSourceUsersDn() {
		return sourceUsersDn;
	}

	/**
	 * @param sourceUsersDn
	 */
	@JsonProperty
	public void setSourceUsersDn(String sourceUsersDn) {
		this.sourceUsersDn = sourceUsersDn;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getConnectionString() {
		return connectionString;
	}

	/**
	 * @param connectionString
	 */
	@JsonProperty
	public void setConnectionString(String connectionString) {
		this.connectionString = connectionString;
	}

	/**
	 * @return String
	 */
	public String getAttrsMap() {
		return attrsMap;
	}

	/**
	 * @param attrsMap
	 */
	public void setAttrsMap(String attrsMap) {
		this.attrsMap = attrsMap;
	}

	/**
	 * @return true/false
	 */
	@JsonProperty
	public boolean isReadOnly() {
		return readOnly;
	}

	/**
	 * @param readOnly
	 */
	public void setReadOnly(boolean readOnly) {
		this.readOnly = readOnly;
	}

	/**
	 * @return String
	 */
	public String getLdapType() {
		return ldapType;
	}

	/**
	 * @param ldapType
	 */
	public void setLdapType(String ldapType) {
		this.ldapType = ldapType;
	}

	/**
	 * @return
	 */
	public String getResourceSetID() {
		return resourceSetID;
	}
	
	/**
	 * @param resourceSetID
	 */
	public void setResourceSetID(String resourceSetID) {
		this.resourceSetID = resourceSetID;
	}

}
