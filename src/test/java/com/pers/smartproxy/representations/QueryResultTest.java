package com.pers.smartproxy.representations;

import static io.dropwizard.testing.FixtureHelpers.fixture;
import static org.fest.assertions.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.dropwizard.jackson.Jackson;

public class QueryResultTest {
	
	private static final ObjectMapper MAPPER = Jackson.newObjectMapper();

    @Test
    public void serializesToJSON() throws Exception {
    	Entry entry =  new DefaultEntry();
        final QueryResult queryResult = new QueryResult(entry);
        queryResult.setDn("test Dn");
        queryResult.setServerName("test server");
        List<String> atrs = new ArrayList<String>();
        atrs.add("attrs");
        queryResult.setAttributes(atrs);
        queryResult.setExceptionMsg(null);
             
        assertThat(MAPPER.writeValueAsString(queryResult))
                .isEqualTo(fixture("queryResult.json"));
    }

}
