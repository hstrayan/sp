package com.pers.smartproxy.representations;

import static io.dropwizard.testing.FixtureHelpers.fixture;
import static org.fest.assertions.api.Assertions.assertThat;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.dropwizard.jackson.Jackson;

public class TenancyTest {
	private static final ObjectMapper MAPPER = Jackson.newObjectMapper();

	@Test
	public void serializesToJSON() throws Exception {
		final Tenancy tenancy = new Tenancy();
		tenancy.setTenantName("coke");
		tenancy.setSourceTenantDn("ou=tenants,o=coke");
		tenancy.setSourceUsersDn("ou=users,ou=tenants,o=coke");
		tenancy.setConnectionString("l27.0.0.1:389:uid=admin,ou=system,secret");

	//	assertThat(MAPPER.writeValueAsString(tenancy)).isEqualTo(fixture("tenancy.json"));
	}

}
