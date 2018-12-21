package com.pers.smartproxy.operations;

import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class DeleteOperationTest {

	@Mock
	LdapConnection connection;

	@Mock
	DeleteOperation deleteOperation;
	
	@Mock
	ModifyRequest modifyRequest;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testDeleteOperation() throws LdapException {
		Dn dn = new Dn("cn=test1,ou=people,o=emc");
		
		doNothing().when(deleteOperation).performOperation(new LdapNetworkConnection(), dn);
		doCallRealMethod().when(deleteOperation).performOperation(connection, dn);
		deleteOperation.performOperation(connection, dn);
		verify(deleteOperation).performOperation(connection, dn);
		
		Entry entry  = new DefaultEntry();
		entry.setDn("ou=people,o=emc");
		doNothing().when(deleteOperation).performOperation(connection, entry);
		doCallRealMethod().when(deleteOperation).performOperation(connection, entry);
		deleteOperation.performOperation(connection, entry);
		verify(deleteOperation).performOperation(connection, entry);
	}

	@Test
	public void testDeleteOperationParameters() throws LdapException {
		Dn dn = new Dn("cn=test1,ou=people,o=emc");
		DeleteOperation spy = Mockito.spy(deleteOperation);
		Mockito.doNothing().when(spy).performOperation(connection, dn);
	}
	@Test
	public void testperformOperation() {
		try{
		DeleteOperation delete = new DeleteOperation();
		Dn dn = new Dn("cn=test1,ou=people,o=emc");
		DeleteOperation spy = Mockito.spy(deleteOperation);
		delete.performOperation(new LdapNetworkConnection(), dn, true);
		}catch(Exception e){}
	}
	@Test
	public void testcascadingDeleteAlgorithm()  {
		try{
		DeleteOperation delete = new DeleteOperation();
		Dn dn = new Dn("cn=test1,ou=people,o=emc");
		DeleteOperation spy = Mockito.spy(deleteOperation);
		delete.cascadingDeleteAlgorithm(connection, dn);
		}catch(Exception e){}
	}
	@Test
	public void testimplementDeleteControl()  {
		try {
		DeleteOperation delete = new DeleteOperation();
		Dn dn = new Dn("cn=test1,ou=people,o=emc");
		DeleteOperation spy = Mockito.spy(deleteOperation);
		delete.implementDeleteControl(connection, dn);
		}catch(Exception e){}
	}
	@Test
	public void testsubTreeDeletes()  {
		try {
		DeleteOperation delete = new DeleteOperation();
		Entry entry = new DefaultEntry();
		List<Entry> list = new ArrayList<Entry>();
		list.add(entry);
		
		Dn dn = new Dn("cn=test1,ou=people,o=emc");
		DeleteOperation spy = Mockito.spy(deleteOperation);
		delete.subTreeDeletes(connection, list, 1);
		}catch(Exception e){}
	}
	
	@Test
	public void verifyOverrides() throws LdapException {
		DeleteOperation deleteOperation = new DeleteOperation();
		
		deleteOperation.performOperation(connection, modifyRequest);
		deleteOperation.performOperation(connection, new Dn("o=virtustream"));
		EntryCursor entryCursor = deleteOperation.performOperation(connection, "base dn", "(objectClass=*)",SearchScope.SUBTREE, null);
		assertNull(entryCursor);
		EntryCursor entryCursor2 = deleteOperation.performOperation(connection, new Dn("o=virtustream"), "(objectClass=*)", SearchScope.SUBTREE, null);
		assertNull(entryCursor2);
	}

}
