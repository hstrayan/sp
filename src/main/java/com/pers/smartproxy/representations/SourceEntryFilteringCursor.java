package com.pers.smartproxy.representations;

import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.filtering.EntryFilter;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursorImpl;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;

import java.util.List;

/**
 * Created by pricer3 on 9/5/2017.
 */
public class SourceEntryFilteringCursor extends EntryFilteringCursorImpl {

    public SourceEntryFilteringCursor(Cursor<Entry> wrapped, SearchOperationContext operationContext, SchemaManager schemaManager, EntryFilter filter) {
        super(wrapped, operationContext, schemaManager, filter);
    }

    public SourceEntryFilteringCursor(Cursor<Entry> wrapped, SearchOperationContext operationContext, SchemaManager schemaManager) {
        super(wrapped, operationContext, schemaManager);
    }

    public SourceEntryFilteringCursor(Cursor<Entry> wrapped, SearchOperationContext operationContext, SchemaManager schemaManager, List<EntryFilter> filters) {
        super(wrapped, operationContext, schemaManager, filters);
    }

    @Override
    public void beforeFirst() throws LdapException, CursorException {
        //Don't throw exception
    }
}
