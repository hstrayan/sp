package com.pers.smartproxy;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.codahale.metrics.annotation.Timed;
import com.pers.smartproxy.representations.EndpointConnection;
import com.pers.smartproxy.services.DSEngine;

/**
 * @author sathyh2
 * 
 *         Resource to test endpoint connections
 *
 */
@Path("/v1")
@Produces(MediaType.APPLICATION_JSON)
public class AuthenticationResource {

	final Logger logger = LoggerFactory.getLogger(AuthenticationResource.class);
	/**
	 * Directory Service Engine
	 */
	DSEngine dsEngine = null;
	/*
	 * constructor
	 */

	public AuthenticationResource(final DSEngine dsEngine) {
		this.dsEngine = dsEngine;
	}

	/**
	 * Authenticate
	 * 
	 * @param addOperation
	 * @return String
	 */
	@POST
	@Timed
	@Path("/authenticate")
	public String authenticate(EndpointConnection endpointConnection) {
		String response = validate(endpointConnection);
		if (response != null && response.length() > 0) {
			return response;
		}
		logger.info(endpointConnection.getHostName() + "  " + endpointConnection.getPort());
		logger.info(endpointConnection.getUserName() + "  " + endpointConnection.getPassword());
		try {
			LdapConnection connection = dsEngine.getEmbeddedConnector().getPool().getConnection();
			if (connection != null) {
				logger.info("connection successful");
				return "success";
			}
		} catch (LdapException e) {
			logger.info("LdapException : "+ e);
		}
		return "failure";
	}

	/**
	 * @param endpointConnection
	 * @return
	 */
	private String validate(EndpointConnection endpointConnection) {
		if (endpointConnection.getHostName() == null || endpointConnection.getHostName().isEmpty()) {
			return "invalid Hostname, please refer schema/documentaion";
		}
		if (endpointConnection.getPort() < 389) {
			return "invalid port name, ports need to > 389, please refer schema/documentaion";
		}
		if (endpointConnection.getIPAddress() == null || endpointConnection.getIPAddress().isEmpty()) {
			return "invalid IP address, please refer schema/documentaion";
		}
		if (endpointConnection.getUserName() == null || endpointConnection.getUserName().isEmpty()) {
			return "invalid user name, please refer schema/documentaion";
		}
		if (endpointConnection.getPassword() == null || endpointConnection.getPassword().isEmpty()) {
			return "invalid password, please refer schema/documentaion";
		}
		return null;
	}

}
