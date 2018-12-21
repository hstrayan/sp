package com.pers.smartproxy.representations;

import java.io.IOException;
import java.util.Map;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pers.smartproxy.connectors.ProxyConnector;

/**
 * @author sathyh2
 * 
 *         Tenant class encapsulates all tenancy related attrs and operations
 *
 */
public class Tenant {
	final Logger logger = LoggerFactory.getLogger(Tenant.class);
	private static final String ORGOBJCLS = "objectClass: organizationalUnit";
	private static final String OBJCLS = "objectClass";
	private static final String TENANCY = "tenancy";
	private static final String TENANCYOBJCLS = "objectClass: tenancy";
	private static final String TOPOBJCLS = "objectClass: top";
	private static final String EQUALS = "=";
	private static final String COMMA = ",";
	private static final String COLON = ":";
	private static final String TENANTID = "tenantId";
	private static final String PLACEHOLDER = "placeholderAttrs";

	/**
	 * Tenant DN
	 */
	private String tenantDn;
	/**
	 * Partition Name
	 */
	private String partitionName;
	/**
	 * Embedded LDAP Connection
	 */
	private LdapConnection embeddedConnection;

	/**
	 * External sources connections
	 */
	private Map<String, ProxyConnector> extConnections;

	/**
	 * mappings
	 */
	Map<String, ProxyConfiguration> mappings;

	/**
	 * no-args constructor
	 */
	public Tenant() {
		// default
	}

	/**
	 * Constructor
	 * 
	 * @param tenantDn
	 * @param partitionName
	 * @param embeddedConnection
	 * @param extConnections
	 */
	public Tenant(String tenantDn, String partitionName, LdapConnection embeddedConnection,
			Map<String, ProxyConnector> extConnections) {
		this.tenantDn = tenantDn;
		this.partitionName = partitionName;
		this.embeddedConnection = embeddedConnection;
		this.extConnections = extConnections;
	}

	/**
	 * @return String
	 */
	public String getTenantDn() {
		return tenantDn;
	}

	/**
	 * @param tenantDn
	 */
	public void setTenantDn(String tenantDn) {
		this.tenantDn = tenantDn;
	}

	/**
	 * @return String
	 */
	public String getPartitionName() {
		return partitionName;
	}

	/**
	 * @param partitionName
	 */
	public void setPartitionName(String partitionName) {
		this.partitionName = partitionName;
	}

	/**
	 * @return LdapNetworkConnection
	 */
	public LdapConnection getEmbeddedConnection() {
		return embeddedConnection;
	}

	/**
	 * @param embeddedConnection
	 */
	public void setEmbeddedConnection(LdapConnection embeddedConnection) {
		this.embeddedConnection = embeddedConnection;
	}

	/**
	 * @return Map<String, ProxyConnector>
	 */
	public Map<String, ProxyConnector> getExtConnections() {
		return extConnections;
	}

	/**
	 * @param extConnections
	 */
	public void setExtConnections(Map<String, ProxyConnector> extConnections) {
		this.extConnections = extConnections;
	}

	/**
	 * @return true/false
	 * @throws LdapException
	 * @throws LdapInvalidDnException
	 */
	public boolean doesOuExist() throws LdapException {
		String qualifiedDn = getTenantDn() + COMMA + getPartitionName();
		if (getEmbeddedConnection().exists(new Dn(qualifiedDn))) {
			return true;
		}
		return false;
	}

	/**
	 * Create Tenancy OU
	 * 
	 * @param qualifiedDn
	 * @return true/false
	 */
	public boolean createTenancyOu(String qualifiedDn) {
		String[] dnSplit = getTenantDn().split(EQUALS);
		String qualifiedSubDn = dnSplit[0] + COLON + dnSplit[1];
		try {
			Entry entry = new DefaultEntry(qualifiedDn, ORGOBJCLS, TENANCYOBJCLS, TOPOBJCLS, qualifiedSubDn);
			getEmbeddedConnection().add(entry);
			logger.info("Tenancy OU bootstraped successfully");
			return true;
		} catch (LdapException e) {
			logger.info("Tenancy OU bootstrap failed " + e);
			return false;
		} finally {
			try {
				getEmbeddedConnection().close();
			} catch (IOException e) {
				logger.info("IOException: " + e);
			}
		}
	}

	/**
	 * transform entry to store internally
	 * 
	 * @param entry
	 * @return
	 * @throws LdapException
	 */
	public Entry transformEntryInternal(Entry entry) throws LdapException {
		Attribute attr = new DefaultAttribute(OBJCLS, TENANCY);
		entry.add(attr);
		return entry;
	}

	/**
	 * Algorithm to generate entry based on external attributes
	 * 
	 * @param entry
	 * @return
	 * @throws LdapException
	 * @throws LdapInvalidAttributeValueException
	 */
	public Entry transformEntryExternal(Entry entry, Map<String, String[]> sourceAttrs) throws LdapException {
		Entry newEntry = null;
		for (Map.Entry<String, String[]> map : sourceAttrs.entrySet()) {
			newEntry = new DefaultEntry(entry.getDn());
			String[] mapAttrs = map.getValue();
			for (String sourceAttr : mapAttrs) {
				if (sourceAttr.contains(OBJCLS)) {
					String sourceAttrSplit[] = sourceAttr.split(":");
					if (entry.contains("objectclass", sourceAttrSplit[1].trim())) {
						Attribute obj = new DefaultAttribute(OBJCLS);
						obj.add(sourceAttrSplit[1]);
						newEntry.add(obj);
					}
				} else {
					if (entry.containsAttribute(sourceAttr)) {
						Attribute attr = entry.get(sourceAttr);
						Attribute newAttr = new DefaultAttribute(sourceAttr);
						newAttr.add(attr.getString());
						newEntry.add(newAttr);
					}
				}
			}
		}
		return newEntry;
	}

	/**
	 * Remove all internal attrs before sending it externally
	 * @param entr
	 *  @return
	 * @throws LdapException
	 */
	public Entry transformEntryExternal(Entry entry) throws LdapException {
		if (entry.contains(OBJCLS, TENANCY)) {
			entry.remove(OBJCLS, TENANCY);
		}
		entry.removeAttributes(TENANTID, "connectionString","endpointDn","hasSource","attrsMap","ldapType","readOnly","sourceTenantDn","sourceUsersDn");
		return entry;
	}

}
