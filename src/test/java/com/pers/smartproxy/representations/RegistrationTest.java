package com.pers.smartproxy.representations;

import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;

import com.fasterxml.jackson.databind.ObjectMapper;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.directory.api.ldap.model.exception.LdapException;

import io.dropwizard.jackson.Jackson;
import static io.dropwizard.testing.FixtureHelpers.fixture;

public class RegistrationTest {
	
	  private static final ObjectMapper MAPPER = Jackson.newObjectMapper();
	  Registration reg;
	  
	  @Before
		public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
		}

	    @Test
	    public void serializesToJSON() throws Exception {
	    	 String[] targetDns = {"cn=testadd,ou=system"};
	    	final Registration reg = new Registration("ldapConnector1","vsc1",targetDns,"cn=commonName,uid=oid,x=y" );
			    
	        final String expected = MAPPER.writeValueAsString(
	                MAPPER.readValue(fixture("register.json"), Registration.class));

	        assertThat(MAPPER.writeValueAsString(reg)).isEqualTo(expected);
	    }
	    
	    @Test
	    public void deserializesFromJSON() throws Exception {
	    	 String[] targetDns = {"cn=testadd,ou=system"};
	    	final Registration reg = new Registration("ldapConnector1","vsc1",targetDns,"cn=commonName,uid=oid,x=y" );
			   assertThat(MAPPER.readValue(fixture("register.json"), Registration.class))
	                .isEqualTo(reg);
	    }
	    
	    @Test
	    public void testOtherMethods() throws Exception {
	    	 String[] targetDns = {"cn=testadd,ou=system"};
	    	final Registration reg = new Registration("ldapConnector1","vsc1",targetDns,"cn=commonName,uid=oid,x=y" );
			assertEquals(reg.toString(),"Registration [serverName=ldapConnector1, parentDn=vsc1, targetDns=[cn=testadd,ou=system], mappedAttrs=cn=commonName,uid=oid,x=y]");
			assertNotNull(reg.hashCode());
			assertEquals(true,reg.equals(reg));
	    }

}
