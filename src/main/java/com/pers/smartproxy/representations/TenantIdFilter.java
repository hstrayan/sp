package com.pers.smartproxy.representations;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.server.core.api.filtering.EntryFilter;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;

/**
 * @author sathyh2
 *
 */
public class TenantIdFilter implements EntryFilter {

	private String tenantId;

	/**
	 * @param tenantId
	 */
	public TenantIdFilter(String tenantId) {
		this.tenantId = tenantId;
	}

	/* (non-Javadoc)
	 * @see org.apache.directory.server.core.api.filtering.EntryFilter#accept(org.apache.directory.server.core.api.interceptor.context.SearchOperationContext, org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public boolean accept(SearchOperationContext searchOperationContext, Entry entry) throws LdapException {
		entry.add("tenantId", tenantId);
		return true;
	}

	@Override
	public String toString(String s) {
		return null;
	}
}
