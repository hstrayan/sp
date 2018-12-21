package com.pers.smartproxy;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.representations.User;
import com.pers.smartproxy.services.DSEngine;
import com.pers.smartproxy.utils.Constants;
import com.pers.smartproxy.utils.LdapCrudUtils;

/**
 * @author sathyh2
 *
 *         Authenticating User using Tenant Id
 */
@Path("auth/v1/authenticate")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserTenantAuthResource {
	final Logger logger = LoggerFactory.getLogger(UserTenantAuthResource.class);
	/**
	 * app configuration
	 */
	AppConfig configuration = null;
	/**
	 * directory service engine
	 */
	DSEngine dsEngine = null;

	/**
	 * no args ctr
	 */
	public UserTenantAuthResource() {

	}

	/**
	 * @param dsEngine
	 * @param configuration
	 */
	public UserTenantAuthResource(final DSEngine dsEngine, final AppConfig configuration) {
		this.configuration = configuration;
		this.dsEngine = dsEngine;
	}

	/**
	 * @param tenant
	 * @return Response
	 */
	@POST
	public Response authenticateUser(User user) {
		if ((user.getDistinguishedName() == null))
			return Response.status(Response.Status.BAD_REQUEST).build();
		if (user.getPassword() == null)
			return Response.status(Response.Status.BAD_REQUEST).build();
		// does tenant exist?
		String tenantDn = LdapCrudUtils.getTenantFromDn(user.getDistinguishedName());
		Entry entry = dsEngine.getEmbeddedConnector().lookUpTenantByDn(tenantDn);
		String postMappedDn = null;
		try {
			if (entry != null) {
				// mandatory field
				String sourceUserNode = entry.get(Constants.SOURCEUSERSDN).getString();
				// optional field
				String mappings = entry.get(Constants.ATTRSMAP).getString();
				if (mappings != null && mappings.trim().length() > 0) {
					String userName = LdapCrudUtils.getUserNameFromDn(user.getDistinguishedName());
					postMappedDn = LdapCrudUtils.createDnForTranslation(userName, sourceUserNode, mappings);
				} else {
					postMappedDn = LdapCrudUtils.getFirstPartDn(user.getDistinguishedName()).concat(Constants.COMMA).concat(sourceUserNode);
				}
				if (postMappedDn == null)
					return Response.status(Response.Status.EXPECTATION_FAILED).entity("Invalid Mapping Defined!")
							.build();
				String connectionString = entry.get(Constants.CONNECTIONSTRING).getString();
				String host = dsEngine.getHostNameOrIP(connectionString);
				ProxyConnector connector = getDsEngine().getConnectors().get(host);
				Entry authenticatedUser = connector.authenticateAndGetUser(postMappedDn, user.getPassword());
				if (authenticatedUser != null) {
					User resolvedUser = resolvedUser(authenticatedUser);
					return Response.ok(resolvedUser).build();
				} else
					return Response.status(Response.Status.UNAUTHORIZED).build();
			} else
				return Response.status(Response.Status.NOT_FOUND).entity("No Tenant for Tenant Name Provided!").build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).entity(e.getMessage()).build();
		}
	}


	/**
	 * @param authenticatedUser
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	protected User resolvedUser(Entry authenticatedUser) throws LdapInvalidAttributeValueException {
		User resolvedUser = new User();
		if (authenticatedUser.getDn() != null) {
			resolvedUser.setDistinguishedName(authenticatedUser.getDn().toString());
		}
		if (authenticatedUser.get("cn") != null) {
			resolvedUser.setFirstName(authenticatedUser.get("cn").getString());
		}
		if (authenticatedUser.get("sn") != null) {
			resolvedUser.setLastName(authenticatedUser.get("sn").getString());
		}
		if (authenticatedUser.get("email") != null) {
			resolvedUser.setEmail(authenticatedUser.get("email").getString());
		}
		// TODO: other fields
		return resolvedUser;
	}

	/**
	 * @return AppConfig
	 */
	public AppConfig getConfiguration() {
		return configuration;
	}

	/**
	 * @param configuration
	 */
	public void setConfiguration(AppConfig configuration) {
		this.configuration = configuration;
	}

	/**
	 * @return DSEngine
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
	 * Algorithm to retrieve a mapped Id from String of mapped pairs
	 * 
	 * @param target
	 * @param mod
	 * @return
	 */
	protected String getMappingId(String target, String sourceId) throws IndexOutOfBoundsException {
		String[] mappedAttr;
		int index = target.indexOf(sourceId);
		if (index >= 0) {
			String subString = target.substring(index);
			String[] mappedData = subString.split(Constants.COMMA);
			mappedAttr = mappedData[0].split(Constants.EQUALS);
			if (mappedAttr.length <= 1)
				return mappedAttr[0];
			return mappedAttr[1];
		} else
			return sourceId;
	}

}
