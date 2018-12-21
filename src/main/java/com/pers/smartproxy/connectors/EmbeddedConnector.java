package com.pers.smartproxy.connectors;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.DefaultPoolableLdapConnectionFactory;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.TrustManagerFactory;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;

import com.pers.smartproxy.AppConfig;
import com.pers.smartproxy.operations.DeleteOperation;
import com.pers.smartproxy.representations.Tenancy;
import com.pers.smartproxy.representations.User;
import com.pers.smartproxy.utils.LdapCrudUtils;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.and;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

/**
 * @author sathyh2
 * 
 *         Connector for Embedded Instance
 *
 */
public class EmbeddedConnector {

	final Logger logger = LoggerFactory.getLogger(EmbeddedConnector.class);
	/**
	 * localhost/IP address
	 */
	private String localHost;
	/**
	 * port
	 */
	private int port;

	/**
	 * LdapConnectionPool
	 */
	private LdapConnectionPool pool;
	
	/**
	 * DefaultPoolableLdapConnectionFactory factory
	 */
	private DefaultPoolableLdapConnectionFactory factory;
	
	private LdapConnectionConfig config;
	
	private static final String TENANTBASE = "ou=tenants,o=emc";
	private static final String SOURCETENANTDN = "sourceTenantDn";
	private static final String SOURCEUSERSDN = "sourceUsersDn";
	private static final String ATTRSMAP = "attrsMap";
	private static final String CONNECTIONSTRING = "connectionString";
	private static final String LDAPTYPE = "ldapType";
	private static final String READONLY = "readOnly";
	private static final String TENANTID = "tenantId";
	private static final String DNPREFIX = "ou=";
	private static final String DNSUFFIX = ",ou=tenants,o=emc";
	private static final String USERSOU = "ou=users,";
	private static final String GROUPOU = "ou=groups,";

	

	/**
	 * no-args contructor
	 */
	public EmbeddedConnector() {
	}

	/**
	 * @param userName
	 * @param isSSL 
	 * @param pwd
	 * @return boolean
	 */
	public boolean connect(String localHost, int port, String userName, String credentials, AppConfig config2, boolean isSSL) {
		config = new LdapConnectionConfig();
		if (isSSL) {
			FileInputStream fileInputStream;
			try {
				fileInputStream = new FileInputStream(config2.getCertName());
				KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				String keyPwd = config2.getCertPwd();
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
		config.setLdapHost(localHost);
		config.setLdapPort(port);
		config.setName(userName);
		config.setCredentials(credentials);
		factory = new DefaultPoolableLdapConnectionFactory(config);
		pool = new LdapConnectionPool(factory);
		configurePool();
		try {
			if (pool != null && pool.getConnection().isConnected()) {
				logger.info("embedded connection pool created successfully");
				return true;
			}
		} catch (LdapException e) {
			logger.info("exception : " + e);
		}
		return false;

	}
	
	public synchronized Entry lookUpTenantByDn(String tenantDn) {
		LdapConnection connection = null;
		Entry entry = null;
		try {
			connection = getPool().getConnection();
			entry = connection.lookup(tenantDn);
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}

		return entry;
	}

	/**
	 * @param attrName
	 * @param attrValue
	 * @return
	 */
	public synchronized EntryCursor retrieveAllTenants() {
		EntryCursor entryCursor;
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			entryCursor = connection.search(TENANTBASE,
					and(equal("objectClass", "organizationalUnit"), equal("objectClass", "tenancy")).toString(),
					SearchScope.SUBTREE, new String[] {});
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return entryCursor;
	}

	/**
	 * @param attrName
	 * @param attrValue
	 * @return
	 */
	public synchronized EntryCursor searchTenantByAttr(String attrName, String attrValue) {
		EntryCursor entryCursor;
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			entryCursor = connection.search(TENANTBASE, and(equal(attrName, attrValue),
					equal("objectClass", "organizationalUnit"), equal("objectClass", "tenancy")).toString(),
					SearchScope.SUBTREE, new String[] {});
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return entryCursor;
	}

	/**
	 * @param tenant
	 * @return
	 * @throws LdapException
	 */
	public synchronized String addTenant(Entry tenant) throws LdapException {
		LdapConnection connection = null;
		String tenantId = null;
		try {
			connection = getPool().getConnection();
			tenantId = generateTenantId();
			tenant.add(TENANTID, tenantId);
			connection.add(tenant);
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (Exception e) {
				logger.info("connection closing Exception" + e);
			}
		}

		return tenantId;
	}

	/**
	 * @param tenantDn
	 * @return
	 * @throws LdapException
	 */
	public synchronized Entry getUserEntry(String tenantDn) throws LdapException {
		Entry userOU = new DefaultEntry();
		userOU.setDn(USERSOU + tenantDn);
		userOU.add("objectClass", "organizationalUnit");
		userOU.add("objectClass", "top");
		return userOU;
	}

	/**
	 * @param tenantDn
	 * @return
	 * @throws LdapException
	 */
	public synchronized Entry getGroupEntry(String tenantDn) throws LdapException {
		Entry groupsOU = new DefaultEntry();
		groupsOU.setDn(GROUPOU + tenantDn);
		groupsOU.add("objectClass", "organizationalUnit");
		groupsOU.add("objectClass", "top");
		return groupsOU;
	}

	/**
	 * @param userOu
	 * @throws LdapException
	 */
	public synchronized void addSubTenantOUs(Entry ou) throws LdapException {
		LdapConnection connection = null;

		try {
			connection = getPool().getConnection();
			connection.add(ou);
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
	}

	/**
	 * @return String
	 */
	public String generateTenantId() {
		return UUID.randomUUID().toString();
	}

	/**
	 * @param tenant
	 * @return
	 * @throws LdapException
	 */
	public synchronized Entry getEntryFromTenantObj(Tenancy tenant) throws LdapException {
		Entry newTenant = new DefaultEntry();
		newTenant.setDn(DNPREFIX + tenant.getTenantName() + DNSUFFIX);
		newTenant.add(SOURCETENANTDN, tenant.getSourceTenantDn());
		newTenant.add(SOURCEUSERSDN, tenant.getSourceUsersDn());
		newTenant.add(CONNECTIONSTRING, tenant.getConnectionString());
		newTenant.add(LDAPTYPE, tenant.getLdapType());
		if (tenant.getAttrsMap() != null && tenant.getAttrsMap().length() > 0) {
			newTenant.add(ATTRSMAP, tenant.getAttrsMap());
		} else
			newTenant.add(ATTRSMAP, " ");
		if (tenant.isReadOnly()) {
			newTenant.add(READONLY, "true");
		} else
			newTenant.add(READONLY, "false");
		newTenant.add("endpointDn", DNPREFIX + tenant.getTenantName() + "," + tenant.getSourceTenantDn());
		if (tenant.isReadOnly()) {
			newTenant.add("hasSource", "false");
		} else {
			newTenant.add("hasSource", "true");
		}
		newTenant.add("resourcesetid", tenant.getResourceSetID());
		newTenant.add("objectClass", "organizationalUnit");
		newTenant.add("objectClass", "tenancy");
		newTenant.add("objectClass", "top");

		return newTenant;
	}

	/**
	 * @param dn
	 * @return
	 */
	public synchronized boolean deleteTenantByAttr(Dn dn) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			connection.delete(dn);
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return true;
	}

	/**
	 * @param dn
	 * @return
	 */
	public synchronized boolean deleteByDn(Dn dn) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			connection.delete(dn);
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return true;
	}

	/**
	 * @param dn
	 * @return
	 */
	public synchronized boolean cascadeDeleteTenantByAttr(Dn dn) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			DeleteOperation delete = new DeleteOperation();
			try {
				delete.performOperation(connection, dn, true);
			} catch (CursorException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return true;
	}

	/**
	 * @param origDn
	 * @param tenant
	 * @return
	 */
	public synchronized boolean modifyTenant(String origDn, Tenancy tenant) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			List<Modification> modifications = new ArrayList<>();
			modifications.add(new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, SOURCETENANTDN,
					tenant.getSourceTenantDn()));
			modifications.add(new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, SOURCEUSERSDN,
					tenant.getSourceUsersDn()));
			modifications.add(
					new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, ATTRSMAP, tenant.getAttrsMap()));
			connection.modify(origDn, modifications.toArray(new Modification[modifications.size()]));
		} catch (LdapException e) {
			logger.info("LdapException:" + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return true;
	}

	/**
	 * @param ctr
	 * @return
	 */
	public static String getHostNameOrIP(String ctr) {
		String[] ctrParams = ctr.split(":");
		return ctrParams[0];
	}

	/**
	 * @param userToAdd
	 * @return
	 */
	public synchronized void addUser(Entry userEntry) throws LdapException {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			connection.add(userEntry);
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
	}

	/**
	 * lookup User By DN
	 * 
	 * @param distinguishedName
	 * @return
	 */
	public synchronized User lookUpUserByDn(String searchDn) {
		LdapConnection connection = null;
		User user = null;
		try {
			connection = getPool().getConnection();
			logger.info("search dn " + searchDn);
			EntryCursor cursor = connection.search(searchDn, "(objectclass=*)", SearchScope.SUBTREE);
			if (cursor.next()) {
				logger.info("cursor exisits");
				user = loadUser(cursor.get());
			}
		} catch (Exception e) {
			logger.info("exception " + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return user;
	}

	/**
	 * lookup User EntryBy DN
	 * 
	 * @param distinguishedName
	 * @return
	 */
	public synchronized Entry lookUpUserEntryByDn(String searchDn) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			logger.info("search dn " + searchDn);
			EntryCursor cursor = connection.search(searchDn, "(objectclass=*)", SearchScope.SUBTREE);
			if (cursor.next()) {
				return cursor.get();
			}
		} catch (Exception e) {
			logger.info("exception " + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return null;
	}

	/**
	 * @param entry
	 * @return
	 */
	protected User loadUser(Entry entry) {
		User user = new User();
		user.setDistinguishedName(entry.getDn().getName());
		user.setFirstName(entry.get("cn").toString());
		user.setLastName(entry.get("sn").toString());
		user.setUserName(entry.get("uid").toString());
		if (entry.get("mail") != null) {
			user.setEmail(entry.get("mail").toString());
		}
		user.setTenantID(entry.get("tenantId").toString());
		// TODO: add more fields
		if (entry.get("unicodePwd") != null) {
			// user.setTempPassword(entry.get("unicodePwd").toString());
			user.setSourcePwdUnicode(true);
		} else {
			// user.setTempPassword(entry.get("userPassword").toString());
			user.setSourcePwdUnicode(false);
		}
		return user;

	}

	/**
	 * @param userId
	 * @return
	 */
	public synchronized User lookUpUserByUID(String userId) {
		LdapConnection connection = null;
		User user = null;
		try {
			connection = getPool().getConnection();
			EntryCursor cursor = connection.search("ou=tenants,o=emc", equal("uid", userId).toString(),
					SearchScope.SUBTREE, new String[] {});
			if (cursor != null && cursor.next()) {
				user = loadUser(cursor.get());
			}

		} catch (Exception e) {
			logger.info("exception " + e);
			return null;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return user;
	}

	/**
	 * @param userId
	 * @return
	 */
	public synchronized boolean deleteUserByUserId(String userId) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			EntryCursor cursor = connection.search("ou=tenants,o=emc", equal("uid", userId).toString(),
					SearchScope.SUBTREE, new String[] {});
			if (cursor != null && cursor.next()) {
				Entry entry = cursor.get();
				connection.delete(entry.getDn());
			} else
				return false;
		} catch (Exception e) {
			logger.info("exception " + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return true;
	}

	/**
	 * @param ModifyRequest
	 * @return boolean
	 */
	public synchronized boolean modifyUser(ModifyRequest modifyRequest) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			if (modifyRequest != null) {
				connection.modify(modifyRequest);
			}
		} catch (LdapException e) {
			logger.info("LdapException " + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return true;
	}

	/**
	 * @param ModifyRequest
	 * @return boolean
	 */
	public synchronized boolean modifyUserByEntry(Entry entry) {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			if (entry != null) {
				connection.modify(entry, ModificationOperation.REPLACE_ATTRIBUTE);
			}
		} catch (LdapException e) {
			logger.info("LdapException " + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return true;
	}

	/**
	 * @param userDn
	 * @param oldPwd
	 * @param newPwd
	 * @return
	 */
	public synchronized boolean changePassword(String userDn, String oldPwd, String newPwd) {
		LdapConnection connection = null;
		try {
			logger.info("lookup user");
			User user = lookUpUserByDn(userDn);
			modifyBasedonPwdType(userDn, newPwd, connection, user);
		} catch (LdapException e) {
			logger.info("LdapException " + e);
			return false;
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		return true;
	}

	/**
	 * @param userDn
	 * @param newPwd
	 * @param connection
	 * @param user
	 * @throws LdapException
	 */
	protected void modifyBasedonPwdType(String userDn, String newPwd, LdapConnection connection, User user)
			throws LdapException {
		if (user != null) {
			connection = getPool().getConnection();
			if (user.isSourcePwdUnicode()) {
				connection.modify(userDn, new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "unicodePwd",
						LdapCrudUtils.generateSSHA(newPwd)));
			} else
				connection.modify(userDn, new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE,
						"userPassword", LdapCrudUtils.generateSSHA(newPwd)));
		}
	}

	/**
	 * configure pool
	 */
	protected void configurePool() {
		pool.setTestOnBorrow(true);
		pool.setTestOnReturn(true);
		pool.setTestWhileIdle(true);
		pool.setMaxActive(-1);
		pool.setMaxIdle(10);
		pool.setMinIdle(0);
		pool.setMaxWait(1L);
	}

	/**
	 * @return String
	 */
	public String getLocalHost() {
		return localHost;
	}

	/**
	 * @param localHost
	 */
	public void setLocalHost(String localHost) {
		this.localHost = localHost;
	}

	/**
	 * @return int
	 */
	public int getPort() {
		return port;
	}

	/**
	 * @param port
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * @return LdapConnectionPool
	 */
	public LdapConnectionPool getPool() {
		return pool;
	}

	/**
	 * @param pool
	 */
	public void setPool(LdapConnectionPool pool) {
		this.pool = pool;
	}
	

	/**
	 * @return DefaultPoolableLdapConnectionFactory
	 */
	public DefaultPoolableLdapConnectionFactory getFactory() {
		return factory;
	}

	/**
	 * @param factory
	 */
	public void setFactory(DefaultPoolableLdapConnectionFactory factory) {
		this.factory = factory;
	}
	
	/**
	 * @return LdapConnectionConfig
	 */
	public LdapConnectionConfig getConfig() {
		return config;
	}

	/**
	 * @param config
	 */
	public void setConfig(LdapConnectionConfig config) {
		this.config = config;
	}

	public void addTenantViaIntr(Entry entry) throws LdapException  {
		LdapConnection connection = null;
		try {
			connection = getPool().getConnection();
			connection.add(entry);
		} finally {
			try {
				getPool().releaseConnection(connection);
			} catch (LdapException e) {
				logger.info("connection closing Exception" + e);
			}
		}
		
	}

}
