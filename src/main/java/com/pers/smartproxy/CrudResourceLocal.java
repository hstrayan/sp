//package com.virtustream.coreservices.rolodex;
//
//import java.io.IOException;
//import java.util.ArrayList;
//import java.util.List;
//
//import javax.ws.rs.Consumes;
//import javax.ws.rs.DELETE;
//import javax.ws.rs.POST;
//import javax.ws.rs.Path;
//import javax.ws.rs.Produces;
//import javax.ws.rs.core.MediaType;
//
//import org.apache.directory.api.ldap.model.cursor.CursorException;
//import org.apache.directory.api.ldap.model.cursor.EntryCursor;
//import org.apache.directory.api.ldap.model.entry.DefaultModification;
//import org.apache.directory.api.ldap.model.entry.Modification;
//import org.apache.directory.api.ldap.model.entry.ModificationOperation;
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.apache.directory.api.ldap.model.message.ModifyRequest;
//import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
//import org.apache.directory.api.ldap.model.message.SearchScope;
//import org.apache.directory.api.ldap.model.name.Dn;
//import org.apache.directory.ldap.client.api.LdapNetworkConnection;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//
//import com.codahale.metrics.annotation.Timed;
//import com.virtustream.coreservices.rolodex.connectors.EmbeddedConnector;
//import com.virtustream.coreservices.rolodex.representations.CrudOperation;
//import com.virtustream.coreservices.rolodex.representations.QueryResult;
//import com.virtustream.coreservices.rolodex.utils.JsonLdifConvertor;
//
//@Path("/rolodex")
//@Produces(MediaType.APPLICATION_JSON)
//@Consumes(MediaType.APPLICATION_JSON)
//public class CrudResourceLocal {
//
//	final Logger logger = LoggerFactory.getLogger(CrudResourceLocal.class);
//	/**
//	 * ldapconnection
//	 */
//	LdapNetworkConnection connection = null;
//	/**
//	 * app config
//	 */
//	AppConfig configuration = null;
//	/**
//	 * objectclass used for search by default
//	 */
//	private static String DEFAULTOBJCLS = "(objectClass=*)";
//	/**
//	 * Default error message
//	 */
//	private static String ERRMSG = "Invalid Request";
//	/**
//	 * Invalid DN
//	 */
//	private static String INVALIDDN = "Invalid DN";
//	/**
//	 * Default error message
//	 */
//	private static String INVALIDATTRS = "Invalid Attributes";
//
//	/**
//	 * constructor
//	 * 
//	 * @param dsEngine
//	 * @param configuration
//	 * @throws IOException
//	 * @throws LdapException
//	 */
//	public CrudResourceLocal(final AppConfig configuration) throws IOException, LdapException {
//		this.configuration = configuration;
//		EmbeddedConnector connector = new EmbeddedConnector();
//		connection = connector.connect(configuration.getHostName(), configuration.getPort(),
//				configuration.getLocalUserName(), configuration.getLocalPasswd());
//
//	}
//
//	/*
//	 * @param deleteOperation
//	 * 
//	 * @return
//	 */
//	@DELETE
//	@Timed
//	@Path("/deleteByDnLocal")
//	public String deleteExistingEntry(final CrudOperation deleteOperation) {
//		if (deleteOperation.getDn() == null || deleteOperation.getDn().isEmpty()) {
//			return INVALIDDN;
//		}
//		try {
//			connection.delete(deleteOperation.getDn());
//		} catch (LdapException e) {
//			return e.getMessage();
//		} catch (Exception e) {
//			logger.info(e.getMessage());
//			return e.getMessage();
//		}
//		return "success";
//	}
//
//	/**
//	 * @param modifyOperation
//	 * @return
//	 */
//	@POST
//	@Timed
//	@Path("/modifyAttributesLocal")
//	public String modifyReplaceExistingAttrs(final CrudOperation modifyOperation) {
//		if (modifyOperation.getDn() == null || modifyOperation.getDn().isEmpty()) {
//			return INVALIDDN;
//		}
//		if (modifyOperation.getAttributes() == null || modifyOperation.getAttributes().length == 0) {
//			return INVALIDATTRS;
//		}
//		try {
//			ModifyRequest modifyRequest = new ModifyRequestImpl();
//			modifyRequest.setName(new Dn(modifyOperation.getDn()));
//			String[] attributes = modifyOperation.getAttributes();
//			for (String attribute : attributes) {
//				String[] splitAttr = JsonLdifConvertor.splitAttributes(attribute);
//				Modification mod = new DefaultModification(
//						ModificationOperation.getOperation(modifyOperation.getModifyType()), splitAttr[0].trim(),
//						splitAttr[1].trim());
//				modifyRequest.addModification(mod);
//			}
//			connection.modify(modifyRequest);
//		} catch (LdapException e) {
//			logger.info(e.getMessage());
//			return e.getMessage();
//		} catch (Exception e) {
//			logger.info(e.getMessage());
//			return ERRMSG;
//		}
//		return "success";
//	}
//
//	/**
//	 * @param searchOperation
//	 * @return
//	 */
//	@POST
//	@Timed
//	@Path("/searchLocalByDn")
//	public QueryResult[] searchLocalByDn(final CrudOperation searchOperation) {
//		QueryResult queryResult = null;
//		if (searchOperation.getDn() == null || searchOperation.getDn().isEmpty()) {
//			return customException(INVALIDDN);
//		}
//		if (searchOperation.getAttributes() == null || searchOperation.getAttributes().length == 0) {
//			return customException(INVALIDATTRS);
//		}
//		List<QueryResult> results = new ArrayList<QueryResult>();
//		try {
//			EntryCursor cursor = connection.search(searchOperation.getDn(), DEFAULTOBJCLS, SearchScope.SUBTREE,
//					searchOperation.getAttributes());
//			while (cursor.next()) {
//				queryResult = new QueryResult(cursor.get());
//				results.add(queryResult);
//			}
//		} catch (LdapException | CursorException e) {
//			logger.info(e.getMessage());
//		}
//		QueryResult[] array = results.toArray(new QueryResult[results.size()]);
//		return array;
//	}
//
//	/**
//	 * @param exceptionStr
//	 * @return
//	 */
//	private QueryResult[] customException(String exceptionStr) {
//		List<QueryResult> results = new ArrayList<QueryResult>();
//		QueryResult result = new QueryResult();
//		result.setExceptionMsg(exceptionStr);
//		results.add(result);
//		return results.toArray(new QueryResult[results.size()]);
//	}
//
//}