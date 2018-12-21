package com.pers.smartproxy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.codahale.metrics.annotation.Timed;
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.interceptors.ProxyInterceptor;
import com.pers.smartproxy.representations.CrudOperation;
import com.pers.smartproxy.representations.QueryResult;
import com.pers.smartproxy.services.DSEngine;
import com.pers.smartproxy.utils.JsonLdifConvertor;

@Path("/v1")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class CrudResource {

	final Logger logger = LoggerFactory.getLogger(CrudResource.class);
	/**
	 * connected default to false
	 */
	boolean connected = false;
	/**
	 * ldap connection
	 */
	LdapConnection connection = null;
	/**
	 * app configuration
	 */
	AppConfig configuration = null;
	/**
	 * directory service engine
	 */
	DSEngine dsEngine = null;
	/**
	 * proxy intereceptor
	 */
	ProxyInterceptor proxy = null;
	/**
	 * list of interceptors
	 */
	List<Interceptor> interceptors = null;
	private ProxyInterceptor intr;

	/**
	 * no args ctr
	 */
	public CrudResource() {

	}

	/**
	 * constructor
	 * 
	 * @param dsEngine
	 * @param configuration
	 * @throws IOException
	 * @throws LdapException
	 */
	public CrudResource(final DSEngine dsEngine, final AppConfig configuration) throws IOException, LdapException {
		this.configuration = configuration;
		this.dsEngine = dsEngine;
		connect(configuration);

	}
	// TODO : Bulk Adds

	/**
	 * @param configuration
	 * @throws LdapException
	 */
	protected void connect(final AppConfig configuration) throws LdapException {
		if (getConnection() == null) {
			connection = new LdapNetworkConnection(configuration.getHostName(), configuration.getPort());
		}
		connection.bind(configuration.getLocalUserName(), configuration.getLocalPasswd());
	}

	/**
	 * @param addOperation
	 * @return
	 */
	@POST
	@Timed
	@Path("/addNewEntry")
	public String addNewEntry(final CrudOperation addOperation) {
		if (addOperation.getDn() == null || addOperation.getDn().isEmpty()) {
			return "invalid DN";
		}
		if (addOperation.getAttributes() == null || addOperation.getAttributes().length == 0) {
			return "invalid Attributes";
		}
		Entry entry = null;
		try {
			entry = getEntryFromLdif(addOperation);
			addOperation(entry);
		} catch (LdapException e) {
			logger.info(e.getMessage());
			return e.getMessage();
		}
		return "success";
	}

	protected void addOperation(Entry entry) throws LdapException {
		AddOperationContext addOperationContext = new AddOperationContext(dsEngine.getDsSession(), entry);
		getInterceptor().add(addOperationContext);
	}

	protected Entry getEntryFromLdif(final CrudOperation addOperation) throws LdapException {
		Entry entry;
		entry = JsonLdifConvertor.convertJsonToLdifEntry(addOperation);
		return entry;
	}

	// TODO : bulk deletes
	/**
	 * @param deleteOperation
	 * @return
	 */
	@DELETE
	@Timed
	@Path("/deleteByDn")
	public String deleteExistingEntry(final CrudOperation deleteOperation) {
		if (deleteOperation.getDn() == null || deleteOperation.getDn().isEmpty()) {
			return "invalid DN";
		}
		try {
			logger.info("interceptor " + deleteOperation.getDn());
			DeleteOperationContext deleteOperationContext = new DeleteOperationContext(dsEngine.getDsSession(),
					new Dn(deleteOperation.getDn()));
			getInterceptor().delete(deleteOperationContext);
		} catch (LdapException e) {
			return e.getMessage();
		}
		return "success";
	}

	/**
	 * @param modifyOperation
	 * @return
	 */
	@POST
	@Timed
	@Path("/modifyAttrs")
	public String modifyReplaceExistingAttrs(final CrudOperation modifyOperation) {
		if (modifyOperation.getDn() == null || modifyOperation.getDn().isEmpty()) {
			return "invalid DN";
		}
		if (modifyOperation.getAttributes() == null || modifyOperation.getAttributes().length == 0) {
			return "invalid Attributes";
		}
		try {
			ModifyRequest modifyRequest = new ModifyRequestImpl();
			modifyRequest.setName(new Dn(modifyOperation.getDn()));
			String[] attributes = modifyOperation.getAttributes();
			for (String attribute : attributes) {
				String[] splitAttr = JsonLdifConvertor.splitAttributes(attribute);
				logger.info(splitAttr[0] + " " + splitAttr[1]);
				int modifyType = modifyOperation.getModifyType();
				Modification mod = new DefaultModification(ModificationOperation.getOperation(modifyType),
						splitAttr[0].trim(), splitAttr[1].trim());
				modifyRequest.addModification(mod);
			}
			ModifyOperationContext modifyOperationContext = new ModifyOperationContext(dsEngine.getDsSession(),
					modifyRequest);
			getInterceptor().modify(modifyOperationContext);

		} catch (LdapException e) {
			logger.info(e.getMessage());
			return e.getMessage();
		} catch (Exception e) {
			logger.info(e.getMessage());
			return ("invalid mapping attributes used");
		}
		return "success";
	}

	/**
	 * @param searchOperation
	 * @return
	 * @throws CursorException
	 * @throws LdapException
	 * @throws LdapInvalidDnException
	 */
	@POST
	@Timed
	@Path("/searchByDn")
	public QueryResult[] searchAttrs(final CrudOperation searchOperation) {
		QueryResult queryResult = null;
		if (searchOperation.getDn() == null || searchOperation.getDn().isEmpty()) {
			return customException("invalid DN");
		}
		if (searchOperation.getAttributes() == null || searchOperation.getAttributes().length == 0) {
			return customException("invalid Attributes");
		}
		List<QueryResult> results = new ArrayList<QueryResult>();
		Map<String, ProxyConnector> connectors = dsEngine.getConnectors();
		SearchRequest searchRequest = new SearchRequestImpl();
		try {
			loadSearchRequest(searchOperation, searchRequest);
			SearchOperationContext searchContext = new SearchOperationContext(dsEngine.getDsSession(), searchRequest);
			createQueryResult(results, connectors, searchContext);
		} catch (CursorException | LdapException e) {
			logger.info(e.getMessage());
		}
		return results.toArray(new QueryResult[results.size()]);
	}

	protected void createQueryResult(List<QueryResult> results, Map<String, ProxyConnector> connectors,
			SearchOperationContext searchContext)
			throws CursorException, LdapException, LdapInvalidAttributeValueException {
		QueryResult queryResult;
		for (Map.Entry<String, ProxyConnector> entry : connectors.entrySet()) {
			ProxyConnector connector = entry.getValue();
			EntryCursor entryCursor = connector.searchByDn(searchContext);
			if (entryCursor != null){
			loopEntryCursor(results, entry, entryCursor);
			}
		}
	}

	protected void loopEntryCursor(List<QueryResult> results, Map.Entry<String, ProxyConnector> entry,
			EntryCursor entryCursor) throws LdapException, CursorException, LdapInvalidAttributeValueException {
		QueryResult queryResult;
		while (entryCursor.next()) {
			queryResult = new QueryResult(entryCursor.get());
			queryResult.setServerName(entry.getKey());
			results.add(queryResult);
		}
	}

	/**
	 * To be called for Mapped Proxy Requests
	 * 
	 * @param searchOperation
	 * @return
	 * @throws CursorException
	 * @throws LdapException
	 * @throws LdapInvalidDnException
	 */
	@POST
	@Timed
	@Path("/searchMappedDns")
	public QueryResult[] searchMappedDns(final CrudOperation searchOperation) {
		QueryResult queryResult = null;
		if (searchOperation.getDn() == null || searchOperation.getDn().isEmpty()) {
			return customException("invalid DN");
		}
		if (searchOperation.getAttributes() == null || searchOperation.getAttributes().length == 0) {
			return customException("invalid Attributes");
		}
		List<QueryResult> results = new ArrayList<QueryResult>();
		Map<String, ProxyConnector> connectors = dsEngine.getConnectors();
		try {
			loopThruConnectors(searchOperation, results, connectors);
		} catch (CursorException | LdapException e) {
			logger.info(e.getMessage());
		}
		return results.toArray(new QueryResult[results.size()]);
	}

	protected void loopThruConnectors(final CrudOperation searchOperation, List<QueryResult> results,
			Map<String, ProxyConnector> connectors)
			throws CursorException, LdapInvalidDnException, LdapException, LdapInvalidAttributeValueException {
		for (Map.Entry<String, ProxyConnector> entry : connectors.entrySet()) {
			ProxyConnector connector = entry.getValue();
			List<EntryCursor> entryCursors = connector.searchMappedDns(new Dn(searchOperation.getDn()),
					searchOperation.getAttributes());
			if (!entryCursors.isEmpty() || entryCursors != null) {
				for (EntryCursor entryCursor : entryCursors) {
					loopEntryCursor(results, entry, entryCursor);
				}
			}
		}
	}

	/**
	 * @param exceptionStr
	 * @return
	 */
	protected QueryResult[] customException(String exceptionStr) {
		List<QueryResult> results = new ArrayList<QueryResult>();
		QueryResult result = new QueryResult();
		result.setExceptionMsg(exceptionStr);
		results.add(result);
		return results.toArray(new QueryResult[results.size()]);
	}

	/**
	 * @param searchOperation
	 * @param searchRequest
	 * @throws LdapInvalidDnException
	 * @throws LdapException
	 */
	protected void loadSearchRequest(final CrudOperation searchOperation, final SearchRequest searchRequest)
			throws LdapInvalidDnException, LdapException {
		if (searchOperation.getAttributes().length > 0) {
			logger.info("length is " + searchOperation.getAttributes().length);
			searchRequest.addAttributes(searchOperation.getAttributes());
		} else {
			searchRequest.addAttributes("*");
		}
		// no req on the time-limit
		searchRequest.setTimeLimit(0);
		searchRequest.setBase(new Dn(searchOperation.getDn()));
	}

	/**
	 * @return
	 */
	public DSEngine getDsEngine() {
		return dsEngine;
	}

	/**
	 * @param dsEngine
	 */
	public void setDsEngine(DSEngine dsEngine) {
		this.dsEngine = dsEngine;
	}

	/**
	 * @return
	 */
	public List<Interceptor> getInterceptors() {
		return interceptors;
	}

	/**
	 * @param interceptors
	 */
	public void setInterceptors(List<Interceptor> interceptors) {
		this.interceptors = interceptors;
	}

	/**
	 * @return
	 * @throws LdapException
	 */
	protected ProxyInterceptor getInterceptor() throws LdapException {
		ProxyInterceptor intr = new ProxyInterceptor(configuration);
		intr.setConnectorMap(dsEngine.getConnectors());
		return intr;
	}

	protected void setInterceptor(ProxyInterceptor intr) {
		this.intr = intr;
	}

	/**
	 * @return
	 */
	public LdapConnection getConnection() {
		return connection;
	}

	/**
	 * @param connection
	 */
	public void setConnection(LdapConnection connection) {
		this.connection = connection;
	}

}
