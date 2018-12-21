package com.pers.smartproxy.representations;

import static io.dropwizard.testing.FixtureHelpers.fixture;
import static org.fest.assertions.api.Assertions.assertThat;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.dropwizard.jackson.Jackson;

public class EndpointConnectionTest {
	private static final ObjectMapper MAPPER = Jackson.newObjectMapper();

    @Test
    public void serializesToJSON() throws Exception {
        final EndpointConnection endpointConnection = new EndpointConnection();
        endpointConnection.setHostName("localhost");
        endpointConnection.setIPAddress("127.0.0.1");
        endpointConnection.setUserName("user");
        endpointConnection.setPassword("password1");
        endpointConnection.setPort(10389);
             
        assertThat(MAPPER.writeValueAsString(endpointConnection))
                .isEqualTo(fixture("epConnection.json"));
    }

}
