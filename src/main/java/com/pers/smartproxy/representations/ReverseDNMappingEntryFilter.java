package com.pers.smartproxy.representations;

import com.pers.smartproxy.utils.LdapCrudUtils;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.core.api.filtering.EntryFilter;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by pricer3 on 9/5/2017.
 */
public class ReverseDNMappingEntryFilter implements EntryFilter {
	
	final Logger logger = LoggerFactory.getLogger(ReverseDNMappingEntryFilter.class);

	private String tenantDn, sourceTenantUsersDn, ldapType;

	public ReverseDNMappingEntryFilter(String tenantDn, String sourceTenantUsersDn, String ldapType) {
		this.tenantDn = tenantDn;
		this.sourceTenantUsersDn = sourceTenantUsersDn;
		this.ldapType = ldapType;
	}

	
	public boolean reverseEntryDn(Entry entry) throws LdapException {
		logger.debug("entry is " + entry);
		Dn sourceDn = entry.getDn();
		logger.debug("sourceDn is " + sourceDn);
		logger.debug("tenantDn is " + tenantDn);
		logger.debug("sourceTenantUsersDn is " + sourceTenantUsersDn);
		String updatedSourceDn = null;
		
		if (sourceDn.getName().equalsIgnoreCase(sourceTenantUsersDn)
				|| StringUtils.containsIgnoreCase(sourceDn.getName(), sourceTenantUsersDn)){
           
			if (StringUtils.containsIgnoreCase(sourceDn.getName(), "CN")){
				updatedSourceDn = LdapCrudUtils.getFirstPartDn(sourceDn.getName()).replace("CN", "uid");
				logger.debug("updatedSourceDn is " + updatedSourceDn);
				if (ldapType.equalsIgnoreCase("AD")){
				String[] newDn = sourceDn.getName().split(",");
				String rolodexDn = newDn[0]+","+newDn[1]+","+newDn[2]+",ou=tenants,o=emc";
				String updatedRolodexDn = rolodexDn.replace("CN", "uid");
				entry.put("distinguishedName",updatedRolodexDn);
				removeADAttrs(entry);
				}
				
				logger.debug(entry.toString());
				
			} else {
				updatedSourceDn = LdapCrudUtils.getFirstPartDn(sourceDn.getName());
			}
			 if (LdapCrudUtils.getFirstPartDn(updatedSourceDn).equalsIgnoreCase("ou=users")){
				 if (ldapType.equalsIgnoreCase("AD")){
				 String[] newDn = sourceDn.getName().split(",");
					String rolodexDn = newDn[0]+","+newDn[1]+",ou=tenants,o=emc";
					entry.put("distinguishedName",rolodexDn);
					logger.debug("rolodexDn is " + rolodexDn);
					entry.put("distinguishedName",rolodexDn);
					removeADAttrs(entry);
				 }
	            	entry.setDn(updatedSourceDn.concat(",").concat(tenantDn));
	            	
	           }else
		entry.setDn(updatedSourceDn.concat(",").concat("ou=users").concat(",").concat(tenantDn));
	} else
			entry.setDn(("ou=users").concat(",").concat(tenantDn));
			return true;
	}


	private void removeADAttrs(Entry entry) {
		entry.removeAttributes("objectCategory","sAMAccountName","objectGUID","objectSid");
	}

	@Override
	public boolean accept(SearchOperationContext searchOperationContext, Entry entry) throws LdapException {
		return reverseEntryDn(entry);
	}

	@Override
	public String toString(String s) {
		return null;
	}
}
