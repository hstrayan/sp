package com.pers.smartproxy.health;

import java.util.Map;

import com.codahale.metrics.health.HealthCheck;
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.services.DSEngine;

/**
 * @author sathyh2
 * 
 * Health check to verify if the DS instance is running correctly in an deployed instance
 *
 */
/**
 * External connectors Health Check
 *
 */
public class ExtConnectorsHealthCheck extends HealthCheck {

	/**
	 *  directory services
	 */
	private final DSEngine dsEngine;

	/**
	 * constructor
	 * 
	 * @param dsEngine
	 */
	public ExtConnectorsHealthCheck(DSEngine dsEngine) {
		this.dsEngine = dsEngine;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.codahale.metrics.health.HealthCheck#check()
	 */
	@Override
	protected Result check() throws Exception {
		if (dsEngine.getConnectors() != null && dsEngine.getConnectors().size() > 0) {
			return Result.healthy();
		} else {
			Map<String, ProxyConnector> map = dsEngine.getConnectors();
			StringBuffer sb = new StringBuffer();
			for (Map.Entry<String, ProxyConnector> entry : map.entrySet()) {
				sb.append(entry.getKey());
			}
			return Result.unhealthy("Cannot connect to External DS Sources" + sb.toString());
		}
	}

}
