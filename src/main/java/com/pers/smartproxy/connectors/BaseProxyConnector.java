package com.pers.smartproxy.connectors;

import java.util.Map;

import com.pers.smartproxy.representations.ConnectorInfo;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pers.smartproxy.utils.ConnectionManager;

/**
 * @author sathyh2
 * 
 *         BaseProxyConnector provides connections to the configured LDAP data
 *         sources.
 *
 */
public abstract class BaseProxyConnector {

	final Logger logger = LoggerFactory.getLogger(BaseProxyConnector.class);
	/**
	 * connection manager
	 */
	private ConnectionManager connManager = null;
	/**
	 * connection pool
	 */
	private LdapConnectionPool pool = null;
	/**
	 * connection manager for failover
	 */
	private ConnectionManager connManagerFailOver = null;
	/**
	 * failover pool
	 */
	private LdapConnectionPool failoverPool = null;
	/**
	 * map of configs
	 */
	private Map<String, String> connectorConfig;

	/**
	 * no-args contructor
	 */
	public BaseProxyConnector() {
	}

	/**
	 * constructor
	 * 
	 * @param connectorConfig
	 * @throws LdapException
	 */
	public BaseProxyConnector(final ConnectorInfo connectorInfo) {
       try{
		connManager = new ConnectionManager(connectorInfo);
		pool = connManager.getPool();
		if (pool != null && pool.getConnection().isConnected()) {
			logger.info("endpoint connectionpool to server : " + connectorInfo.getHostname() + " at port "+ connectorInfo.getPort() + " created successfully");
		} 
       }catch(Exception e){
    	   System.out.println("cannot connect to external ldap, problem with ctr");
       }
	}

	/**
	 * @return
	 */
	public ConnectionManager getConnManager() {
		return connManager;
	}

	/**
	 * @param connManager
	 */
	public void setConnManager(final ConnectionManager connManager) {
		this.connManager = connManager;
	}

	/**
	 * @param pool
	 */
	public void setPool(final LdapConnectionPool pool) {
		this.pool = pool;
	}

	/**
	 * @return
	 */
	public LdapConnectionPool getPool() {
		return pool;
	}

	/**
	 * @return
	 */
	public ConnectionManager getConnManagerFailOver() {
		return connManagerFailOver;
	}

	/**
	 * @param connManagerFailOver
	 */
	public void setConnManagerFailOver(ConnectionManager connManagerFailOver) {
		this.connManagerFailOver = connManagerFailOver;
	}

	/**
	 * @return
	 */
	public LdapConnectionPool getFailoverPool() {
		return failoverPool;
	}

	/**
	 * @param failoverPool
	 */
	public void setFailoverPool(LdapConnectionPool failoverPool) {
		this.failoverPool = failoverPool;
	}

}
