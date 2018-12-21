package com.pers.smartproxy;
//package com.virtustream.coreservices.rolodex;
//
//import static org.junit.Assert.assertNotNull;
//
//import java.io.IOException;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Map.Entry;
//import java.util.Set;
//import java.util.SortedMap;
//
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.junit.Before;
//import org.junit.Test;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//
//import com.codahale.metrics.health.HealthCheck.Result;
//import com.virtustream.coreservices.rolodex.representations.CrudOperation;
//import com.virtustream.coreservices.rolodex.representations.QueryResult;
//
//public class CrudResourceLocalTest {
//	private CrudResourceLocal crudResourceLocal;
//	@Mock
//	private AppConfig configuration;
//	@Mock
//	Set<Entry<String, Result>> results;
//	@Mock
//	SortedMap<String, Result> sortedResults;
//	@Mock
//	CrudOperation crudOperation;
//
//	QueryResult[] queryResults;
//
//	@Before
//	public void init() throws LdapException {
//		QueryResult queryResult = new QueryResult();
//		List<QueryResult> results = new ArrayList<QueryResult>();
//		queryResults = results.toArray(new QueryResult[results.size()]);
//		MockitoAnnotations.initMocks(this);
//	}
//
//	@Test
//	public void testInvocation() throws IOException, LdapException {
//		crudResourceLocal = new CrudResourceLocal(configuration);
//		CrudResourceLocal spy = Mockito.spy(crudResourceLocal);
//		assertNotNull(spy.equals(crudResourceLocal));
//		Mockito.when(spy.deleteExistingEntry(crudOperation)).thenReturn("success");
//	}
//}
