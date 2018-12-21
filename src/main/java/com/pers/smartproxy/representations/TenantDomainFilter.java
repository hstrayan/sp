package com.pers.smartproxy.representations;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.server.core.api.filtering.EntryFilter;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;

/**
 * @author sathyh2
 *
 */
public class TenantDomainFilter implements EntryFilter {

	private String tenantDomain;

	/**
	 * @param tenantDomain
	 */
	public TenantDomainFilter(String tenantDomain) {
		this.tenantDomain = tenantDomain;
	}

	/* (non-Javadoc)
	 * @see org.apache.directory.server.core.api.filtering.EntryFilter#accept(org.apache.directory.server.core.api.interceptor.context.SearchOperationContext, org.apache.directory.api.ldap.model.entry.Entry)
	 */
	@Override
	public boolean accept(SearchOperationContext searchOperationContext, Entry entry) throws LdapException {
		entry.add("TenantDomain", tenantDomain);
		return true;
	}

	@Override
	public String toString(String s) {
		return null;
	}
}
