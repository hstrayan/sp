package com.pers.smartproxy.operations;

import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class AddOperationTest {

	@Mock
	LdapConnection connection;

	@Mock
	AddOperation addOperation;
	
	@Mock
	ModifyRequest modifyReuqest;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testAddOperation() throws LdapException {

		Entry newEntry = new DefaultEntry("cn=test1,ou=people,o=emc", "ObjectClass: top", "ObjectClass: person",
				"cn: ldap-user", "sn: user");

		doNothing().when(addOperation).performOperation(connection, newEntry);
		doCallRealMethod().when(addOperation).performOperation(connection, newEntry);
		addOperation.performOperation(connection, newEntry);

		verify(addOperation).performOperation(connection, newEntry);
	}

	@Test
	public void testAddOperationParameters() throws LdapException {
		Entry newEntry = new DefaultEntry("cn=test1,ou=people,o=emc", "ObjectClass: top", "ObjectClass: person",
				"cn: ldap-user", "sn: user");
		AddOperation spy = Mockito.spy(addOperation);
		Mockito.doNothing().when(spy).performOperation(connection, newEntry);
	}
	
	@Test
	public void verifyOverrides() throws LdapException {
		AddOperation addOperation = new AddOperation();
		addOperation.performOperation(connection, modifyReuqest);
		addOperation.performOperation(connection, new Dn("o=virtustream"));
		EntryCursor entryCursor = addOperation.performOperation(connection, "base dn", "(objectClass=*)",SearchScope.SUBTREE, null);
		assertNull(entryCursor);
		EntryCursor entryCursor2 = addOperation.performOperation(connection, new Dn("o=virtustream"), "(objectClass=*)", SearchScope.SUBTREE, null);
		assertNull(entryCursor2);
	}

}
