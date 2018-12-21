package com.pers.smartproxy.handlers;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.junit.Before;
import org.junit.Test;

import com.pers.smartproxy.handlers.PatternHandler;

public class PatternHandlerTest {

	PatternHandler patternHander = null;

	@Before
	public void setUp() {
		patternHander = new PatternHandler();

	}

	@Test
	public void testReplaceDnPart() throws LdapInvalidDnException {

		String regex = "o";
		String input = "o=virtustream";
		String target = "com";
		String output = patternHander.replaceDnPart(input, target, regex);
		assertEquals("com=virtustream", output);
	}

	@Test
	public void testReplaceDnStr() throws LdapInvalidDnException {

		String regex = "dc";
		String input = "dc=virtustream, dc=com";
		String target = "o";
		String output = patternHander.replaceDnStr(input, target, regex);
		assertEquals("o=virtustream, o=com", output);
	}

	@Test
	public void testReplaceEntry() {

		Entry expectedResult = null;
		try {
			expectedResult = new DefaultEntry("cn=test1,ou=people,o=emc", "ObjectClass: top", "ObjectClass: person",
					"user: ldap-user", "sn: user");
		} catch (LdapException e1) {
			e1.printStackTrace();
		}

		Entry entry = null;
		try {
			entry = new DefaultEntry("cn=test1,ou=people,o=emc", "ObjectClass: top", "ObjectClass: person",
					"cn: ldap-user", "sn: user");
		} catch (LdapException e) {
			e.printStackTrace();
		}

		Entry output = null;
		try {

			output = patternHander.modifyEntry(entry, "cn", "user");
		} catch (LdapInvalidAttributeValueException e) {
			e.printStackTrace();
		}

		assertEquals(expectedResult, output);

	}

	@Test
	public void testInsertAttrs() {
		String base = "dc=virtustream, dc=records";
		String replacement = "com";
		String endpoint = "cn=test,ou=people";
		String desiredResult = "com=virtustream, dc=records";
		String desiredJoinedResult = "com=virtustream, dc=records,cn=test,ou=people";
		String regex = "(o)|(ou)|(dc)";

		String trandformedDn = patternHander.replacefirstPartDn(regex, base, replacement);

		assertEquals(desiredResult, trandformedDn);

		String joinedResult = patternHander.joinNamespaces(trandformedDn, endpoint);

		assertEquals(desiredJoinedResult, joinedResult);

	}


}
