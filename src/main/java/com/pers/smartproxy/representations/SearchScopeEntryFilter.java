package com.pers.smartproxy.representations;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.server.core.api.filtering.EntryFilter;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;

/**
 * Created by pricer3 on 9/6/2017.
 */
public class SearchScopeEntryFilter implements EntryFilter {
    @Override
    public boolean accept(SearchOperationContext searchOperationContext, Entry entry) throws LdapException {
        if(searchOperationContext.getScope() == SearchScope.ONELEVEL)
            if (entry.getDn().equals(searchOperationContext.getDn()))
                return false;

        return true;
    }

    @Override
    public String toString(String s) {
        return null;
    }
}
