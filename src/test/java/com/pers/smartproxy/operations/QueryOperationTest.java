package com.pers.smartproxy.operations;
//package com.virtustream.coreservices.rolodex.operations;
//
//import static org.junit.Assert.assertEquals;
//import static org.junit.Assert.assertNull;
//import static org.mockito.Mockito.doCallRealMethod;
//import static org.mockito.Mockito.verify;
//
//import org.apache.directory.api.ldap.model.cursor.EntryCursor;
//import org.apache.directory.api.ldap.model.entry.Entry;
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.apache.directory.api.ldap.model.message.ModifyRequest;
//import org.apache.directory.api.ldap.model.message.SearchScope;
//import org.apache.directory.api.ldap.model.name.Dn;
//import org.apache.directory.ldap.client.api.LdapConnection;
//import org.junit.Before;
//import org.junit.Test;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//
//public class QueryOperationTest {
//
//	private static final String TESTDN = "o=virtustream,ou=people";
//
//	@Mock
//	LdapConnection connection;
//
//	@Mock
//	QueryOperation queryOperation;
//
//	@Mock
//	EntryCursor cursor;
//	
//	@Mock
//	ModifyRequest modifyRequest;
//	
//	@Mock
//	Entry entry;
//
//	@Before
//	public void init() throws LdapException {
//		MockitoAnnotations.initMocks(this);
//	}
//
//	@Test
//	public void testQueryOperation() throws LdapException {
//
//		doCallRealMethod().when(queryOperation).performOperation(connection, TESTDN, "*.*", SearchScope.SUBTREE, null);
//		queryOperation.performOperation(connection, TESTDN, "*.*", SearchScope.SUBTREE, null);
//		verify(queryOperation).performOperation(connection, TESTDN, "*.*", SearchScope.SUBTREE, null);
//
//		Mockito.when(queryOperation.performOperation(connection, TESTDN, "*.*", SearchScope.SUBTREE, null))
//				.thenReturn(cursor);
//		assertEquals(queryOperation.performOperation(connection, TESTDN, "*.*", SearchScope.SUBTREE, null), cursor);
//	}
//
//	@Test
//	public void verifyOverrides() throws LdapException {
//		QueryOperation queryOperation = new QueryOperation();
//		queryOperation.performOperation(connection, entry);
//		queryOperation.performOperation(connection, modifyRequest);
//		queryOperation.performOperation(connection, new Dn("o=virtustream"));
//		EntryCursor entryCursor = queryOperation.performOperation(connection, "base dn", "(objectClass=*)",SearchScope.SUBTREE, null);
//		assertNull(entryCursor);
//		EntryCursor entryCursor2 = queryOperation.performOperation(connection, new Dn("o=virtustream"), "(objectClass=*)",SearchScope.SUBTREE, "test");
//		assertNull(entryCursor2);
//		String[] attrs = {"cn","sn"};
//		EntryCursor entryCursor3 = queryOperation.performOperation(connection, new Dn("o=virtustream"), "(objectClass=*)",SearchScope.SUBTREE, attrs);
//		assertNull(entryCursor3);
//	}
//}
