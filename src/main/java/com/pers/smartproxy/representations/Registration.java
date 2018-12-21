package com.pers.smartproxy.representations;

import java.util.Arrays;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author sathyh2
 * 
 *         CRUD representation object
 *
 */
public class Registration {

	/**
	 * server name
	 */
	@NotNull
	private String serverName;
	
	/**
	 *  parent Dn
	 */
	@NotNull
	private String parentDn;
		/**
	 * target/child dn
	 */
	@NotNull
	private String[] targetDns;
	/**
	 * mapping attrs
	 */
	private String mappedAttrs;
	
	/**
	 * no-args constructor
	 */
	public Registration() {
       
    }
	/**
	 * @param serverName
	 * @param parentDn
	 * @param targetDns
	 * @param mappedAttrs
	 */
	public Registration(String serverName, String parentDn, String[] targetDns, String mappedAttrs) {
		super();
		this.serverName = serverName;
		this.parentDn = parentDn;
		this.targetDns = targetDns;
		this.mappedAttrs = mappedAttrs;
	}


	/**
	 * @return
	 */
	@JsonProperty
	public String getServerName() {
		return serverName;
	}
	/**
	 * @param sourceDn
	 */
	@JsonProperty
	public void setServerName(String serverName) {
		this.serverName = serverName;
	}
	
	/**
	 * @return
	 */
	public String getParentDn() {
		return parentDn;
	}
	/**
	 * @param parentDn
	 */
	public void setParentDn(String parentDn) {
		this.parentDn = parentDn;
	}
	
	/**
	 * @return
	 */
	@JsonProperty
	public String[] getTargetDns() {
		return targetDns;
	}
	/**
	 * @param targetDns
	 */
	@JsonProperty
	public void setTargetDns(String[] targetDns) {
		this.targetDns = targetDns;
	}
	/**
	 * @return
	 */
	@JsonProperty
	public String getMappedAttrs() {
		return mappedAttrs;
	}
	/**
	 * @param mappedAttrs
	 */
	@JsonProperty
	public void setMappedAttrs(String mappedAttrs) {
		this.mappedAttrs = mappedAttrs;
	}
	
	
	@Override
	public String toString() {
		return "Registration [serverName=" + serverName + ", parentDn=" + parentDn + ", targetDns="
				+ Arrays.toString(targetDns) + ", mappedAttrs=" + mappedAttrs + "]";
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((mappedAttrs == null) ? 0 : mappedAttrs.hashCode());
		result = prime * result + ((parentDn == null) ? 0 : parentDn.hashCode());
		result = prime * result + ((serverName == null) ? 0 : serverName.hashCode());
		result = prime * result + Arrays.hashCode(targetDns);
		return result;
	}
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Registration other = (Registration) obj;
		if (mappedAttrs == null) {
			if (other.mappedAttrs != null)
				return false;
		} else if (!mappedAttrs.equals(other.mappedAttrs))
			return false;
		if (parentDn == null) {
			if (other.parentDn != null)
				return false;
		} else if (!parentDn.equals(other.parentDn))
			return false;
		if (serverName == null) {
			if (other.serverName != null)
				return false;
		} else if (!serverName.equals(other.serverName))
			return false;
		if (!Arrays.equals(targetDns, other.targetDns))
			return false;
		return true;
	}

}
