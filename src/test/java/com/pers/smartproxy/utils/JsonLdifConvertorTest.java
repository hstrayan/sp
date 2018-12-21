package com.pers.smartproxy.utils;

import static org.junit.Assert.assertEquals;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.representations.CrudOperation;

/**
 * @author sathyh2
 *
 */
public class JsonLdifConvertorTest {

	@Before
	public void init() {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testJsonLdifConvertor() throws LdapException {

		CrudOperation operation = prepareCrudOperation();
		Entry expectedEntry = prepareExpectedEntry(operation);

		Entry resultEntry = JsonLdifConvertor.convertJsonToLdifEntry(operation);

		assertEquals(expectedEntry, resultEntry);

	}

	private Entry prepareExpectedEntry(CrudOperation operation)
			throws LdapInvalidDnException, LdapInvalidAttributeValueException, LdapException {
		Entry expectedEntry = new DefaultEntry();
		expectedEntry.setDn(new Dn("cn=testadd,ou=system"));
		Attribute objectClasses = new DefaultAttribute("objectClass");
		if (operation.getObjectClass() != null) {
			for (String s : operation.getObjectClass()) {
				objectClasses.add(s);
			}
			expectedEntry.add(objectClasses);
		}
		Attribute attribute = new DefaultAttribute("cn");
		attribute.add("testadd_cn");
		expectedEntry.add(attribute);
		return expectedEntry;
	}

	private CrudOperation prepareCrudOperation() {
		CrudOperation operation = new CrudOperation();
		operation.setDn("cn=testadd,ou=system");
		String[] objectClass = { "mapper", "top" };
		operation.setObjectClass(objectClass);
		operation.setFilter("(objectClass=*)");
		operation.setScope("sub");
		String[] atts = { "cn: testadd_cn" };
		operation.setAttributes(atts);
		return operation;
	}

}
