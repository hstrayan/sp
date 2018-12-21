package com.pers.smartproxy.representations;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author sathyh2
 * 
 *         CRUD representation object
 *
 */
public class CrudOperation {

	/**
	 * distinguished name
	 */
	private String dn;
	/**
	 * root dn
	 */
	private String rootDn;
	/**
	 * child dn
	 */
	private String childDn;
	/**
	 * array of objectclasses
	 */
	private String[] objectClass;

	/**
	 * entry attribute
	 */
	private String attribute;

	/**
	 * array of attributes
	 */
	private String[] attributes;
	/**
	 * scope
	 */
	private String scope;

	/**
	 * array of attributes
	 */
	private String filter;
	/**
	 * modify type 0=add,1=remove,2=replace
	 */
	private int modifyType;
	
	/**
	 * no-args contructor
	 */
	public CrudOperation() {
		
	}
	
	

	/**
	 * 
	 * @return
	 */
	@JsonProperty
	public String getRootDn() {
		return rootDn;
	}

	/**
	 * @param rootDn
	 */
	@JsonProperty
	public void setRootDn(String rootDn) {
		this.rootDn = rootDn;
	}

	@JsonProperty
	public String getChildDn() {
		return childDn;
	}

	/**
	 * @param childDn
	 */
	@JsonProperty
	public void setChildDn(String childDn) {
		this.childDn = childDn;
	}

	/**
	 * @return
	 */
	@JsonProperty
	public String[] getObjectClass() {
		return objectClass;
	}

	/**
	 * @param objectClass
	 */
	@JsonProperty
	public void setObjectClass(String[] objectClass) {
		this.objectClass = objectClass;
	}

	/**
	 * @return
	 */
	public String getAttribute() {
		return attribute;
	}

	/**
	 * @param attribute
	 */
	public void setAttribute(String attribute) {
		this.attribute = attribute;
	}

	/**
	 * @return
	 */
	@JsonProperty
	public String[] getAttributes() {
		return attributes;
	}

	/**
	 * @param attributes
	 */
	@JsonProperty
	public void setAttributes(String[] attributes) {
		this.attributes = attributes;
	}

	/**
	 * @return
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
	 * @return
	 */
	@JsonProperty
	public String getScope() {
		return scope;
	}

	/**
	 * @param scope
	 */
	@JsonProperty
	public void setScope(String scope) {
		this.scope = scope;
	}

	/**
	 * @return
	 */
	@JsonProperty
	public String getFilter() {
		return filter;
	}

	/**
	 * @param filter
	 */
	@JsonProperty
	public void setFilter(String filter) {
		this.filter = filter;
	}
	
	/**
	 * @return int
	 */
	@JsonProperty
	public int getModifyType() {
		return modifyType;
	}

	/**
	 * @param modifyType
	 */
	@JsonProperty
	public void setModifyType(int modifyType) {
		this.modifyType = modifyType;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((attribute == null) ? 0 : attribute.hashCode());
		result = prime * result + Arrays.hashCode(attributes);
		result = prime * result + ((childDn == null) ? 0 : childDn.hashCode());
		result = prime * result + ((dn == null) ? 0 : dn.hashCode());
		result = prime * result + ((filter == null) ? 0 : filter.hashCode());
		result = prime * result + modifyType;
		result = prime * result + Arrays.hashCode(objectClass);
		result = prime * result + ((rootDn == null) ? 0 : rootDn.hashCode());
		result = prime * result + ((scope == null) ? 0 : scope.hashCode());
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
		CrudOperation other = (CrudOperation) obj;
		if (attribute == null) {
			if (other.attribute != null)
				return false;
		} else if (!attribute.equals(other.attribute))
			return false;
		if (!Arrays.equals(attributes, other.attributes))
			return false;
		if (childDn == null) {
			if (other.childDn != null)
				return false;
		} else if (!childDn.equals(other.childDn))
			return false;
		if (dn == null) {
			if (other.dn != null)
				return false;
		} else if (!dn.equals(other.dn))
			return false;
		if (filter == null) {
			if (other.filter != null)
				return false;
		} else if (!filter.equals(other.filter))
			return false;
		if (modifyType != other.modifyType)
			return false;
		if (!Arrays.equals(objectClass, other.objectClass))
			return false;
		if (rootDn == null) {
			if (other.rootDn != null)
				return false;
		} else if (!rootDn.equals(other.rootDn))
			return false;
		if (scope == null) {
			if (other.scope != null)
				return false;
		} else if (!scope.equals(other.scope))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "CrudOperation [dn=" + dn + ", rootDn=" + rootDn + ", childDn=" + childDn + ", objectClass="
				+ Arrays.toString(objectClass) + ", attribute=" + attribute + ", attributes="
				+ Arrays.toString(attributes) + ", scope=" + scope + ", filter=" + filter + ", modifyType=" + modifyType
				+ "]";
	}
}
