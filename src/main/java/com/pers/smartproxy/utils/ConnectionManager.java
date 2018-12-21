package com.pers.smartproxy.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Map;

import javax.net.ssl.TrustManagerFactory;

import com.pers.smartproxy.representations.ConnectorInfo;

import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.directory.ldap.client.api.DefaultLdapConnectionFactory;
import org.apache.directory.ldap.client.api.DefaultPoolableLdapConnectionFactory;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.ValidatingPoolableLdapConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author sathyh2
 * 
 *         Connection Manager class that provides a pool of LDAP based
 *         connections to the caller
 *
 */
public final class ConnectionManager {

	final Logger logger = LoggerFactory.getLogger(ConnectionManager.class);
	/**
	 * Connection pool
	 */
	private LdapConnectionPool pool = null;
	/**
	 * FileInputStream
	 */
	FileInputStream fileInputStream = null;

	/**
	 * constructor
	 * 
	 * @param configuration
	 *            Map<String, String>
	 * @throws IOException
	 */

	public ConnectionManager(ConnectorInfo connectorInfo) {
		try{
		if ((pool == null) || pool.isClosed()) {
			final LdapConnectionConfig config = new LdapConnectionConfig();
			if (connectorInfo.isUseTLS()) {
				FileInputStream fileInputStream;
				try {
					fileInputStream = new FileInputStream(connectorInfo.getKeyStorePath());
					KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
					String keyPwd = connectorInfo.getKeyStorePwd();
					char[] password = new String(keyPwd).toCharArray();
					keyStore.load(fileInputStream, password);
					fileInputStream.close();
					TrustManagerFactory trustManagerFactory = TrustManagerFactory
							.getInstance(TrustManagerFactory.getDefaultAlgorithm());
					trustManagerFactory.init(keyStore);
					config.setTrustManagers(trustManagerFactory.getTrustManagers());
					config.setUseSsl(true);
				} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
					e.printStackTrace();
				}
			}
			config.setLdapHost(connectorInfo.getHostname());
			config.setLdapPort(connectorInfo.getPort());
			String userName;
			if (connectorInfo.getUsername().contains("%20")){
				userName = connectorInfo.getUsername().replace("%20", " ");
			} else userName = connectorInfo.getUsername();
			config.setName(userName);
			// there is a problem with parsing passwords with $, this has been handled
			//within docker-compose(maybe a docker bug)
			config.setCredentials(connectorInfo.getPassword());
			
			connectionPoolParameters(config);
		}
		}catch(Exception e){
			System.out.println("connection lost...");
		}
	}

	/**
	 * no-args constructor
	 */
	public ConnectionManager() {
	}

	/**
	 * TODO - this needs to be moved to config
	 * 
	 * @param config
	 */
	private void connectionPoolParameters(final LdapConnectionConfig config) {
		
		DefaultLdapConnectionFactory factory = new DefaultLdapConnectionFactory( config );
		//30 secs
		factory.setTimeOut( 30000 );
        // additional connection optimization parameters
		// values below are defaults as per ApacheDS documentation
		// TODO: Need to test this and calibrate via integration test if need be
		GenericObjectPool.Config poolConfig = new GenericObjectPool.Config();
		poolConfig.lifo = true;
		poolConfig.maxActive = 10;
		poolConfig.maxIdle = 10;
		poolConfig.minIdle = 0;
		
		// ValidatingPoolableLdapConnectionFactory to handle re-binds on multiple users 
		pool = new LdapConnectionPool(
			    new ValidatingPoolableLdapConnectionFactory( factory ), poolConfig );
	}

	/**
	 * return connectionpool object
	 * 
	 * @return LdapConnectionPool
	 */
	public LdapConnectionPool getPool() {
		return pool;
	}

	/**
	 * set connectionpool object
	 * 
	 * @param pool
	 */
	public void setPool(LdapConnectionPool pool) {
		this.pool = pool;
	}

}
