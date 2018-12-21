package com.pers.smartproxy;

import java.util.Map.Entry;
import java.util.Set;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.codahale.metrics.health.HealthCheck.Result;
import com.codahale.metrics.health.HealthCheckRegistry;

/**
 * @author sathyh2
 * 
 * Custom Healthcheck interface to access health of Rolodex components
 *
 */
@Produces(MediaType.APPLICATION_JSON)
@Path("/v1")
public class HealthCheckResource {

	/**
	 *  healthcheck registry
	 */
	private HealthCheckRegistry registry;

	/**
	 * constructor
	 * @param registry
	 */
	public HealthCheckResource(HealthCheckRegistry registry) {
		this.registry = registry;
	}

	/**
	 * get all healthchecks from registry
	 * @return
	 */
	@GET
	@Path("/health")
	public Set<Entry<String, Result>> getStatus() {
		return registry.runHealthChecks().entrySet();
	}

}
