package com.pers.smartproxy.representations;

import static io.dropwizard.testing.FixtureHelpers.fixture;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.jackson.Jackson;

public class CrudOperationTest {

	private static final ObjectMapper MAPPER = Jackson.newObjectMapper();
	Registration reg;

	@Before
	public void init() throws LdapException {

		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void serializeAddToJSON() throws Exception {
		final CrudOperation crud = new CrudOperation();
		crud.setDn("cn=testadd,ou=system");
		String[] objectClass = { "top", "person" };
		crud.setObjectClass(objectClass);
		String[] attrs = { "cn: testadd_cn", "sn: testadd_sn" };
		crud.setAttributes(attrs);

		final String expected = MAPPER.writeValueAsString(MAPPER.readValue(fixture("add.json"), CrudOperation.class));

		assertThat(MAPPER.writeValueAsString(crud)).isEqualTo(expected);
	}

	@Test
	public void serializeModifyToJSON() throws Exception {
		final CrudOperation crud = new CrudOperation();
		crud.setDn("cn=testmodify,ou=system");
		String[] attrs = { "sn: test_modified" };
		crud.setAttributes(attrs);
		// add
		crud.setModifyType(0);

		final String expected = MAPPER
				.writeValueAsString(MAPPER.readValue(fixture("modify.json"), CrudOperation.class));

		assertThat(MAPPER.writeValueAsString(crud)).isEqualTo(expected);
	}

	@Test
	public void serializeDeleteToJSON() throws Exception {
		final CrudOperation crud = new CrudOperation();
		crud.setDn("cn=testdelete,ou=system");
		final String expected = MAPPER
				.writeValueAsString(MAPPER.readValue(fixture("delete.json"), CrudOperation.class));

		assertThat(MAPPER.writeValueAsString(crud)).isEqualTo(expected);
	}

	@Test
	public void serializeSearchToJSON() throws Exception {
		final CrudOperation crud = new CrudOperation();
		crud.setDn("cn=testadd,ou=system");
		crud.setScope("sub");
		crud.setFilter("(cn=testadd)");
		String[] attrs = { "cn" };
		crud.setAttributes(attrs);

		final String expected = MAPPER
				.writeValueAsString(MAPPER.readValue(fixture("search.json"), CrudOperation.class));

		assertThat(MAPPER.writeValueAsString(crud)).isEqualTo(expected);
	}

	@Test
	public void deserializeAddFromJSON() throws Exception {
		final CrudOperation crud = new CrudOperation();
		crud.setDn("cn=testadd,ou=system");
		String[] objectClass = { "top", "person" };
		crud.setObjectClass(objectClass);
		String[] attrs = { "cn: testadd_cn", "sn: testadd_sn" };
		crud.setAttributes(attrs);
		assertThat(MAPPER.readValue(fixture("add.json"), CrudOperation.class)).isEqualTo(crud);
	}

	@Test
	public void deserializeModifyFromJSON() throws Exception {
		final CrudOperation crud = new CrudOperation();
		crud.setDn("cn=testmodify,ou=system");
		String[] attrs = { "sn: test_modified" };
		crud.setAttributes(attrs);
		// add
		crud.setModifyType(0);
		assertThat(MAPPER.readValue(fixture("modify.json"), CrudOperation.class)).isEqualTo(crud);
	}

	@Test
	public void deserializeDeleteFromJSON() throws Exception {
		final CrudOperation crud = new CrudOperation();
		crud.setDn("cn=testdelete,ou=system");
		assertThat(MAPPER.readValue(fixture("delete.json"), CrudOperation.class)).isEqualTo(crud);
	}

	@Test
	public void deserializeSearchFromJSON() throws Exception {
		final CrudOperation crud = new CrudOperation();
		crud.setDn("cn=testadd,ou=system");
		crud.setScope("sub");
		crud.setFilter("(cn=testadd)");
		String[] attrs = { "cn" };
		crud.setAttributes(attrs);
		assertThat(MAPPER.readValue(fixture("search.json"), CrudOperation.class)).isEqualTo(crud);
	}
	
	  @Test
	    public void testOtherMethods() throws Exception {
		  final CrudOperation crud = new CrudOperation();
		   crud.setRootDn("root Dn");
		   crud.setChildDn("child Dn");
		   crud.setAttribute("attr");
			crud.setDn("cn=testadd,ou=system");
			crud.setScope("sub");
			crud.setFilter("(cn=testadd)");
			String[] attrs = { "cn" };
			crud.setAttributes(attrs);
			assertEquals(crud.toString(),"CrudOperation [dn=cn=testadd,ou=system, rootDn=root Dn, childDn=child Dn, objectClass=null, attribute=attr, attributes=[cn], scope=sub, filter=(cn=testadd), modifyType=0]");
			assertNotNull(crud.hashCode());
			assertEquals(true,crud.equals(crud));
	    }

}
