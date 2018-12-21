package com.pers.smartproxy.representations;

import static io.dropwizard.testing.FixtureHelpers.fixture;
import static org.fest.assertions.api.Assertions.assertThat;
import org.junit.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.jackson.Jackson;

public class EndPointTest {
	
	private static final ObjectMapper MAPPER = Jackson.newObjectMapper();

    @Test
    public void serializesToJSON() throws Exception {
        final Endpoint endpoint = new Endpoint();
        endpoint.setServerName("localhost");
        endpoint.setServerIP("127.0.0.1");
        endpoint.setServerLocation(null);
      
        
        
        assertThat(MAPPER.writeValueAsString(endpoint))
                .isEqualTo(fixture("testserver.json"));
    }

}
