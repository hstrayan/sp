package com.pers.smartproxy.health;

import com.codahale.metrics.health.HealthCheck;
import com.pers.smartproxy.services.DSEngine;

/**
 * @author sathyh2
 * 
 * Health check to verify if the DS instance is running correctly in an deployed instance
 *
 */
public class DirectorySvcsHealthCheck extends HealthCheck {

	/**
	 *  directory services
	 */
	private DSEngine dsEngine;

	/**
	 * constructor
	 *  @param dsEngine
	 */
	public DirectorySvcsHealthCheck(DSEngine dsEngine) {
		this.dsEngine = dsEngine;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.codahale.metrics.health.HealthCheck#check()
	 */
	@Override
	protected Result check() throws Exception {
		if (dsEngine.getService().isStarted()) {
			return Result.healthy();
		} else {
			return Result.unhealthy("Cannot connect to Embedded DS Instance!!");
		}
	}
	
	/**
	 * @return DSEngine
	 */
	public DSEngine getDsEngine() {
		return dsEngine;
	}


	public void setDsEngine(DSEngine dsEngine) {
		this.dsEngine =  dsEngine;
	}
}
