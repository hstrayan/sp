package com.pers.smartproxy.operations;

import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class ModifyOperationTest {

	private static final String TESTDN = "o=virtustream,ou=people";

	@Mock
	LdapConnection connection;
	@Mock
	ModifyOperation modifyOperation;
	@Mock
	ModifyRequest modifyRequest;
	@Mock
	Entry entry;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testModifyOperation() throws LdapException {

		ModifyRequest modifyRequest = new ModifyRequestImpl();
		modifyRequest.setName(new Dn(TESTDN));
		Modification mod = new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "cn", "user", "name");
		modifyRequest.addModification(mod);

		doNothing().when(modifyOperation).performOperation(connection, modifyRequest);
		doCallRealMethod().when(modifyOperation).performOperation(connection, modifyRequest);
		modifyOperation.performOperation(connection, modifyRequest);
		verify(modifyOperation).performOperation(connection, modifyRequest);
	}

	@Test
	public void testAddOperationParameters() throws LdapException {
		ModifyRequest modifyRequest = new ModifyRequestImpl();
		modifyRequest.setName(new Dn(TESTDN));
		Modification mod = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "sn", "user", "name");
		modifyRequest.addModification(mod);

		ModifyOperation spy = Mockito.spy(modifyOperation);
		Mockito.doNothing().when(spy).performOperation(connection, modifyRequest);
	}

	@Test
	public void verifyOverrides() throws LdapException {
		ModifyOperation modifyOperation = new ModifyOperation();
		modifyOperation.performOperation(connection, modifyRequest);
		modifyOperation.performOperation(connection, entry);
		modifyOperation.performOperation(connection, new Dn("o=virtustream"));
		EntryCursor entryCursor = modifyOperation.performOperation(connection, "base dn", "(objectClass=*)",SearchScope.SUBTREE, null);
		assertNull(entryCursor);
		EntryCursor entryCursor2 = modifyOperation.performOperation(connection, new Dn("o=virtustream"), "(objectClass=*)", SearchScope.SUBTREE, null);
		assertNull(entryCursor2);
	}
}
