package com.pers.smartproxy.interceptors;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.entry.ClonedServerEntry;
import org.apache.directory.server.core.api.filtering.EntryFilter;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.BaseInterceptor;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.api.interceptor.context.CompareOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.GetRootDseOperationContext;
import org.apache.directory.server.core.api.interceptor.context.HasEntryOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveAndRenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveOperationContext;
import org.apache.directory.server.core.api.interceptor.context.RenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.api.interceptor.context.UnbindOperationContext;
import org.apache.directory.server.core.shared.DefaultCoreSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.pers.smartproxy.AppConfig;
import com.pers.smartproxy.connectors.DefaultProxyConnector;
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.representations.AttributeTypeEntryFilter;
import com.pers.smartproxy.representations.ConnectorInfo;
import com.pers.smartproxy.representations.Enums;
import com.pers.smartproxy.representations.ReverseDNMappingEntryFilter;
import com.pers.smartproxy.representations.SourceEntryFilteringCursor;
import com.pers.smartproxy.representations.Tenancy;
import com.pers.smartproxy.representations.Tenant;
import com.pers.smartproxy.representations.TenantIdFilter;
import com.pers.smartproxy.representations.User;
import com.pers.smartproxy.services.DSEngine;
import com.pers.smartproxy.utils.Constants;
import com.pers.smartproxy.utils.LdapCrudUtils;
import com.pers.smartproxy.utils.RandomStringGenerator;

/**
 * @author sathyh2
 * 
 *         TenancyInterceptor intercepts the LDAP requests impacting the tenancy
 *         portion of the Rolodex Schema and performs a set of actions (TBD)
 *
 */

public class TenancyInterceptor extends BaseInterceptor {

	final Logger logger = LoggerFactory.getLogger(TenancyInterceptor.class);

	private LdapNetworkConnection embeddedConnection = null;
	private String partitionName = null;
	private Tenant tenant = null;
	private Map<String, ProxyConnector> connectorMap = null;
	private AppConfig config;
	private DSEngine dsEngine;
	private ConcurrentHashMap<String, org.apache.directory.api.ldap.model.entry.Entry> tenants;
	private static final String UID = "uid";
	private static final String ADMAPPING = "uid=cn,userPassword=UnicodePwd";
	private static final String UNICODEPASSWORD = "unicodePassword";
	private static final String USERPASSWORD = "userPassword";
	
	private static final String USERSOU = "ou=users";
	private static final String SOURCEDNSTR = "ou=tenants,dc=deadbolt,dc=emc";
	private static final String SEARCHBASESTR = "ou=tenants,o=emc";
	private String fullDn = null;
	private String sourceUserDn = null;

	private ConnectorInfo defaultConnector;
	
	/**
	 * default constructor
	 */
	public TenancyInterceptor() {
		// no-args ctr
	}
	
	/**
	 * @param configuration
	 * @param directoryService
	 * @param tenants
	 * @throws LdapException
	 */
	public TenancyInterceptor(AppConfig configuration, DirectoryService directoryService,
			ConcurrentHashMap<String, org.apache.directory.api.ldap.model.entry.Entry> tenants, ConnectorInfo defaultConnector) throws LdapException {
		this.config = configuration;
		this.directoryService = directoryService;
		this.tenants = tenants;
		this.defaultConnector = defaultConnector;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#add(org.
	 * apache.directory.server.core.api.interceptor.context.AddOperationContext)
	 */
	@Override
	public synchronized void add(AddOperationContext addContext) throws LdapException {
		logger.debug("Add request intercepted");
		if (dsEngine.isFullyLoaded()) {
			Entry entry = addContext.getEntry();
			String origTenantDn = entry.getDn().getName();
			String tempPwd;
			if (entry.getDn().getName().contains(Enums.LdapAttributes.UID.toString())) {
				String userDn = entry.getDn().getName();
				String firstName = entry.get(Enums.LdapAttributes.CN.toString()).getString();
				String lastName = entry.get(Enums.LdapAttributes.SN.toString()).getString();
				String mail = entry.get(Enums.LdapAttributes.MAIL.toString()).getString();
				if (entry.containsAttribute(Enums.LdapAttributes.TEMPPWD.toString())
						&& entry.get(Enums.LdapAttributes.TEMPPWD.toString()) != null) {
					tempPwd = entry.get(Enums.LdapAttributes.TEMPPWD.toString()).getString();
				} else {
					tempPwd = RandomStringGenerator.generateRandomString(48);
				}
				String tenantToCheck = LdapCrudUtils.getTenantNameFromDn(entry.getDn().getName());
				Entry tenantEntry = tenants.get(tenantToCheck);
				if (tenantEntry != null) {			
					String mappings = getMappings(tenantEntry);
					String host = getHostName(tenantEntry);
					System.out.println("host is " + host);
					String userName = LdapCrudUtils.getUserNameFromDn(userDn);
					System.out.println("userName is " + userName);
					String postMappedDn = getPostMappedDn(mappings,
							tenantEntry.get(Constants.SOURCEUSERSDN).getString(), userName);
					System.out.println("postMappedDn is " + postMappedDn);
					if (host != null) {
						ProxyConnector connector = getConnectorMap().get(host);				
						String ldapType = tenantEntry.get(Enums.CustomAttributes.LDAPTYPE.toString()).getString();
						User user = new User();
						user.setFirstName(firstName);
						user.setLastName(lastName);
						user.setEmail(mail);
						if (ldapType.equalsIgnoreCase("AD")) {
							user.setSourcePwdUnicode(true);					
						} else {
							user.setSourcePwdUnicode(false);
						}

						createAndAddEntrySource(tempPwd, user, mappings, postMappedDn, connector, ldapType);
					}
				
				}
			} else if (StringUtils.containsIgnoreCase(origTenantDn, "ou=users"))
				next(addContext);

			else {
				logger.debug("Attempting to add new tenant..");
				ConnectorInfo connectorInfo = null;
				// tenantDomain check
				if (entry.get("tenantDomain") == null) throw new LdapException(" tenantdomain is a required field");
				if (! LdapCrudUtils.getTenantNameFromDn(origTenantDn).equalsIgnoreCase(entry.get("tenantDomain").getString()))
					throw new LdapException("tenantname and tenantdomain do not match");
				if(! LdapCrudUtils.isValidTenantStruct(entry.getDn().getName())) throw new LdapException("Invalid Tenant Dn, please follow ou=<tenantname>,ou=tenants,o=emc");
			   // provide all attrs, not default
				if (entry.get(Enums.CustomAttributes.CONNECTIONSTRING.toString())!=null && entry.get(Enums.CustomAttributes.SOURCETENANTDN.toString())!=null) {
					if (!entry.containsAttribute(Enums.CustomAttributes.SOURCEUSERSDN.toString()))
						throw new LdapException(" Require souce User DN");
					if (!entry.containsAttribute(Enums.CustomAttributes.LDAPTYPE.toString()))
					    throw new LdapException(" Require LdapType");
					if (!entry.containsAttribute(Enums.CustomAttributes.READONLY.toString()))
						throw new LdapException(" Require readOnly flag");
					if (!entry.containsAttribute(Enums.CustomAttributes.ATTRIBUTEMAP.toString()))
						throw new LdapException("Require Attribute Map");
					connectorInfo = new ConnectorInfo(
							entry.get(Enums.CustomAttributes.CONNECTIONSTRING.toString()).getString());
					connectorInfo
							.setSourceTenantDn(entry.get(Enums.CustomAttributes.SOURCETENANTDN.toString()).toString());
					connectorInfo
							.setSourceUsersDn(entry.get(Enums.CustomAttributes.SOURCEUSERSDN.toString()).toString());
					connectorInfo.setLdapType(entry.get(Enums.CustomAttributes.LDAPTYPE.toString()).toString());
					connectorInfo.setReadOnly(
							Boolean.parseBoolean(entry.get(Enums.CustomAttributes.READONLY.toString()).toString()));
					connectorInfo.setAttributeMap(entry.get(Enums.CustomAttributes.ATTRIBUTEMAP.toString()).toString());
					
				} 
				// if AD is the default.  if default flag is set to false, we are not using AD
				else if (defaultConnector!= null ){
					if (defaultConnector.getDefault().equalsIgnoreCase("true") && defaultConnector.getLdapType().equalsIgnoreCase("AD")){
					connectorInfo = new ConnectorInfo(config.getDefaultADconnStr());
					entry.add(Enums.CustomAttributes.SOURCETENANTDN.toString(), config.getDefaultADTenantDn());
					String connStr;
					if (config.getDefaultADconnStr().contains("%20")){
						connStr = config.getDefaultADconnStr().replace("%20", " ");
					} else connStr = config.getDefaultADconnStr();
					entry.add(Enums.CustomAttributes.CONNECTIONSTRING.toString(), connStr);
					entry.add("ldapType", "AD");
					connectorInfo.setSourceTenantDn(config.getDefaultADTenantDn());
					if (entry.get(Enums.CustomAttributes.READONLY.toString())==null) {	
						entry.add(Enums.CustomAttributes.READONLY.toString(),"false");
						connectorInfo.setReadOnly(false);
					} else {
						if (entry.get(Enums.CustomAttributes.READONLY.toString()).getString().equalsIgnoreCase("true")){
							connectorInfo.setReadOnly(true);
						} else connectorInfo.setReadOnly(false);
					}
					if (entry.get(Enums.CustomAttributes.SOURCEUSERSDN.toString())==null){
					String firstPart = LdapCrudUtils.getFirstPartDn(entry.getDn().getName());
					String sourceUsersDn = "ou=users,".concat(firstPart).concat(",").concat(config.getDefaultADTenantDn());
					connectorInfo.setSourceUsersDn(sourceUsersDn);
					entry.add(Enums.CustomAttributes.SOURCEUSERSDN.toString(), sourceUsersDn);
					} else{
						connectorInfo.setSourceUsersDn(entry.get(Enums.CustomAttributes.SOURCEUSERSDN.toString()).getString());
					}
					
					entry.add(Enums.CustomAttributes.ATTRIBUTEMAP.toString(),ADMAPPING);
					connectorInfo.setAttributeMap(ADMAPPING);
					}
				} else { //openldap
					connectorInfo = config.getDefaultConnector();
					if (connectorInfo != null) {
						entry.add(Enums.CustomAttributes.CONNECTIONSTRING.toString(), connectorInfo.toString());
						entry.add(Enums.CustomAttributes.SOURCETENANTDN.toString(), connectorInfo.getSourceTenantDn());
						// for openldap, we are following this usersDn structure
						String sourceUsersDn = "ou=users,".concat(LdapCrudUtils.getFirstPartDn(entry.getDn().getName())).concat(",").concat(connectorInfo.getSourceTenantDn());
						connectorInfo.setSourceUsersDn(sourceUsersDn);
						entry.add(Enums.CustomAttributes.SOURCEUSERSDN.toString(), sourceUsersDn);
						entry.add(Enums.CustomAttributes.LDAPTYPE.toString(), connectorInfo.getLdapType());
						entry.add(Enums.CustomAttributes.READONLY.toString(), Boolean.toString(connectorInfo.isReadOnly()));
						if (!Strings.isNullOrEmpty(connectorInfo.getAttributeMap()))
							entry.add(Enums.CustomAttributes.ATTRIBUTEMAP.toString(), connectorInfo.getAttributeMap());
					}
				}

				logger.debug("connectorInfo == null : " + (connectorInfo == null));
				
				// preprocess
				logger.debug("preprocess");
				if (!getConnectorMap().containsKey(connectorInfo.getHostname())) {
					preProcess(connectorInfo.getHostname(), connectorInfo);
				}

				String attrsMap = null;
				if (entry.containsAttribute(Enums.CustomAttributes.ATTRIBUTEMAP.toString())) {
					if (!entry.get(Enums.CustomAttributes.ATTRIBUTEMAP.toString()).getString().equalsIgnoreCase("NULL")
							|| !entry.get(Enums.CustomAttributes.ATTRIBUTEMAP.toString()).getString()
									.equalsIgnoreCase("")) {
						attrsMap = entry.get(Enums.CustomAttributes.ATTRIBUTEMAP.toString()).getString();
					}
				}

				String tenantName = LdapCrudUtils.getTenantNameFromDn(entry.getDn().getName());
				String sourceTenantDn = entry.get(Enums.CustomAttributes.SOURCETENANTDN.toString()).getString();
				String sourceUsersDn = entry.get(Enums.CustomAttributes.SOURCEUSERSDN.toString()).getString();
				
				if (!entry.containsAttribute(Enums.CustomAttributes.SOURCEUSERSDN.toString())) {
					entry.add(Enums.CustomAttributes.SOURCEUSERSDN.toString(), LdapCrudUtils.createSourceUsersDn(
							tenantName, entry.get(Enums.CustomAttributes.SOURCETENANTDN.toString()).getString()));
				}

				// tenant Id
				String tenantId;
				if (entry.get("tenantId")!=null){
				 tenantId = entry.get("tenantId").getString();
				} else {
					tenantId = dsEngine.getEmbeddedConnector().generateTenantId();	
				}
				Tenancy tenant = createTenantObject(tenantId, sourceTenantDn,
						sourceUsersDn, attrsMap, tenantName);
				entry.add(Enums.CustomAttributes.TENANTID.toString(), tenantId);
				entry.add(Enums.CustomAttributes.HASSOURCE.toString(), "true");
				// add to source first if it is WRITE mode
				// if (!connectorInfo.isReadOnly()) {
				if (!entry.get("readOnly").getString().equals("true")) {
					logger.debug("Writing to source: " + entry);
					Entry sourceEntry = createEntryForSource(tenant);
					logger.debug("Writing to sourceEntry: " + sourceEntry);
					String hostNameInMap = connectorInfo.getHostname();
					logger.debug("hostNameInMap: " + hostNameInMap);
					processSourceInsert(tenant, hostNameInMap, sourceEntry);
					logger.debug("after processSourceInsert: " );
				}
				// local insert
				logger.debug("Writing to local: " + entry);
				String dn = entry.getDn().getName();
				String tName = LdapCrudUtils.getTenantNameFromDn(dn);
				dsEngine.addTenantsRunTime(tName, addContext.getEntry());
				
				//next(addContext);
			}
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#bind(org
	 * .apache.directory.server.core.api.interceptor.context.
	 * BindOperationContext)
	 */
	@Override
	public void bind(BindOperationContext bindContext) throws LdapException {
		String userDn = bindContext.getDn().getName();
		if (StringUtils.containsIgnoreCase(bindContext.getDn().getName(), "ou=users")) {	
			String tenantDn = LdapCrudUtils.getTenantDnFromUserDn(bindContext.getDn().getName());
			String tenantToCheck = LdapCrudUtils.getTenantNameFromDn(tenantDn);
			Entry tenantEntry = tenants.get(tenantToCheck);
			String lookupDn = tenantEntry.getDn().getName();
				if (lookupDn.equalsIgnoreCase(tenantDn)) {
					String mappings = null;
					if (getMappings(tenantEntry) != null) {
						mappings = getMappings(tenantEntry);
					}
					String host = getHostName(tenantEntry);
					String userName = LdapCrudUtils.getUserNameFromDn(userDn);
					String postMappedDn = getPostMappedDn(mappings,
							tenantEntry.get(Constants.SOURCEUSERSDN).getString(), userName);
					Dn distinguishedName = new Dn(this.schemaManager, userDn);
					LdapPrincipal principal = new LdapPrincipal(this.schemaManager, distinguishedName,
							AuthenticationLevel.SIMPLE);
					ProxyConnector connector = dsEngine.getConnectors().get(host);
					if (connector == null) {
						connector = instantiateConnector(tenantEntry.get(Constants.CONNECTIONSTRING).getString());
					}
					BindResponse res = null;
					if	(StringUtils.containsIgnoreCase(postMappedDn,"uid")  ||
								StringUtils.containsIgnoreCase(postMappedDn,"CN")){	
						connector.bind(postMappedDn, bindContext.getCredentials());
					}
					bindContext.setSession(new DefaultCoreSession(principal, this.directoryService));
				}
		} else {
			next(bindContext);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#compare(
	 * org.apache.directory.server.core.api.interceptor.context.
	 * CompareOperationContext)
	 */
	@Override
	public boolean compare(CompareOperationContext compareContext) throws LdapException {
		return next(compareContext);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#delete(
	 * org.apache.directory.server.core.api.interceptor.context.
	 * DeleteOperationContext)
	 */
	@Override
	public void delete(DeleteOperationContext deleteContext) throws LdapException {
		String searchBase = deleteContext.getDn().getName();
		if (StringUtils.containsIgnoreCase(searchBase, "ou=tenants")) {
			String tenantToCheck = LdapCrudUtils.getTenantNameFromDn(searchBase);
			Entry tenantEntry = tenants.get(tenantToCheck);
			if (tenantEntry != null) {
				String currentTenantDN = tenantEntry.getDn().getName();
				String mappings = getMappings(tenantEntry);
				String host = getHostName(tenantEntry);
				if (!tenantEntry.containsAttribute(Enums.CustomAttributes.SOURCEUSERSDN.toString()))
					// TODO Add Message
					throw new LdapException();
				String tenantUserSearchBase = tenantEntry.get(Constants.SOURCEUSERSDN).getString();
				try {
					if (searchBase.equalsIgnoreCase(currentTenantDN)) {
						if (tenantEntry.containsAttribute(Enums.CustomAttributes.SOURCETENANTDN.toString())) {
							ProxyConnector connector = dsEngine.getConnectors().get(host);
							String tenantOU = LdapCrudUtils.getFirstPartDn(currentTenantDN);
							Dn sourceTenantDN = new Dn(tenantOU.concat(",").concat(
									tenantEntry.get(Enums.CustomAttributes.SOURCETENANTDN.toString()).getString()));
							Entry sourceTenantOU = connector
									.lookup(new LookupOperationContext(deleteContext.getSession(), sourceTenantDN));
							if (sourceTenantOU != null) {
								connector.cascadeDelete(sourceTenantOU.getDn());
							}

							deleteContext.setEntry(new DefaultEntry(deleteContext.getDn()));
							next(deleteContext);
						}
				//	} else if (searchBase.contains("ou=users,".concat(currentTenantDN))) {
					} else	if (StringUtils.containsIgnoreCase(searchBase, "ou=users,".concat(currentTenantDN))) {
						if (host != null) {
							ProxyConnector connector = dsEngine.getConnectors().get(host);
							if (searchBase.equalsIgnoreCase("ou=users,".concat(currentTenantDN))) {
								Entry sourceUsersOU = connector.lookup(new LookupOperationContext(
										deleteContext.getSession(), new Dn(tenantUserSearchBase)));
								if (sourceUsersOU != null) {
									connector.cascadeDelete(sourceUsersOU.getDn());
								}

								deleteContext.setEntry(new DefaultEntry(deleteContext.getDn()));
								next(deleteContext);
							} else {
								String firstPartDn = LdapCrudUtils.getFirstPartDn(searchBase);
								String postMappedDn = rolodexDnToSource(mappings, tenantUserSearchBase, firstPartDn);
								connector.cascadeDelete(new Dn(postMappedDn));
								return;
							}
						}
					}
				} catch (Exception ex) {
					deleteContext.setEntry(new DefaultEntry(deleteContext.getDn()));
					return;
				}
			}
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.apache.directory.server.core.api.interceptor.BaseInterceptor#
	 * getRootDse(org.apache.directory.server.core.api.interceptor.context.
	 * GetRootDseOperationContext)
	 */
	@Override
	public Entry getRootDse(GetRootDseOperationContext getRootDseContext) throws LdapException {
		return next(getRootDseContext);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#hasEntry
	 * (org.apache.directory.server.core.api.interceptor.context.
	 * HasEntryOperationContext)
	 */
	@Override
	public boolean hasEntry(HasEntryOperationContext hasEntryContext) throws LdapException {
		return next(hasEntryContext);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#lookup(
	 * org.apache.directory.server.core.api.interceptor.context.
	 * LookupOperationContext)
	 */
	@Override
	public Entry lookup(LookupOperationContext lookupContext) throws LdapException {
		logger.debug("Intercepted lookup");
		Entry entry;
		String lookupDn = lookupContext.getDn().getName();
		if (StringUtils.containsIgnoreCase(lookupDn, "ou=tenants")){
			String tenantToCheck = LdapCrudUtils.getTenantNameFromDn(lookupDn);
			if (tenantToCheck != null) {
				Entry tenantEntry = tenants.get(tenantToCheck);
				String currentTenantDN = tenantEntry.getDn().getName();
				logger.debug("currentTenantDN " + currentTenantDN);
				String mappings = getMappings(tenantEntry);
				logger.debug("mappings " + mappings);
				String host = getHostName(tenantEntry);
				logger.debug("host " + host);
				String ldapType = tenantEntry.get("ldapType").getString();
				String tenantUserSearchBase = tenantEntry.get(Constants.SOURCEUSERSDN).getString();
				logger.debug("tenantUserSearchBase " + tenantUserSearchBase);
				if (lookupDn.equalsIgnoreCase(currentTenantDN))
					return next(lookupContext);

				if (StringUtils.containsIgnoreCase(lookupDn, "ou=users")){
					logger.debug("contains ou=users ");
					if (host != null) {
						try {
							ProxyConnector connector = dsEngine.getConnectors().get(host);
							if (connector != null) {
								logger.debug("connector not null ");
							} else
								logger.debug("connector  null ");

							if (lookupDn.equalsIgnoreCase("ou=users,".concat(currentTenantDN)))
								return next(lookupContext);

							else {
								String firstPartDn = LdapCrudUtils.getFirstPartDn(lookupDn);
								String postMappedDn = rolodexDnToSource(mappings, tenantUserSearchBase, firstPartDn);
								lookupContext.setDn(new Dn(postMappedDn.toLowerCase()));
								entry = connector.lookup(lookupContext);

								ClonedServerEntry clonedServerEntry = new ClonedServerEntry(entry);
								AttributeTypeEntryFilter.SetAttributeTypes(clonedServerEntry);
								ReverseDNMappingEntryFilter reverseDNMappingEntryFilter = new ReverseDNMappingEntryFilter(
										"ou=users,".concat(currentTenantDN), tenantUserSearchBase,ldapType);
								reverseDNMappingEntryFilter.reverseEntryDn(clonedServerEntry);

								return clonedServerEntry;
							}
				
						} catch (Exception ex) {
							return next(lookupContext);
						}
					}
				}
			}
		}
		return next(lookupContext);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#modify(
	 * org.apache.directory.server.core.api.interceptor.context.
	 * ModifyOperationContext)
	 */
	@Override
	public void modify(ModifyOperationContext modifyContext) throws LdapException {
		String searchBase = modifyContext.getDn().getName();
		if (StringUtils.containsIgnoreCase(searchBase, ",ou=tenants")){
			String tenantToCheck = LdapCrudUtils.getTenantNameFromDn(searchBase);
			Entry tenantEntry = tenants.get(tenantToCheck);
			if (tenantEntry != null){
				String currentTenantDN = tenantEntry.getDn().getName();
				String mappings = getMappings(tenantEntry);
				String host = getHostName(tenantEntry);
				if (!tenantEntry.containsAttribute(Enums.CustomAttributes.SOURCEUSERSDN.toString()))
					// TODO Add Message
					throw new LdapException();
				String tenantUserSearchBase = tenantEntry.get(Constants.SOURCEUSERSDN).getString();

				if (searchBase.equalsIgnoreCase(currentTenantDN)) {
					Entry tenantOU = lookup(new LookupOperationContext(modifyContext.getSession(),
							modifyContext.getDn(), "*", "entryUUID"));
					modifyContext.setEntry(tenantOU);
					next(modifyContext);
			
				} else if (StringUtils.containsIgnoreCase(searchBase, "ou=users,".concat(currentTenantDN))){	
					if (host != null) {
						ProxyConnector connector = dsEngine.getConnectors().get(host);
						String ldapType = tenantEntry.get(Enums.CustomAttributes.LDAPTYPE.toString()).getString();
						if (!searchBase.equalsIgnoreCase("ou=users,".concat(currentTenantDN))) {
							String firstPartDn = LdapCrudUtils.getFirstPartDn(searchBase);
							String postMappedDn = rolodexDnToSource(mappings, tenantUserSearchBase, firstPartDn);
															
							connector.modify(new ModifyOperationContext(modifyContext.getSession(),
									new Dn(postMappedDn), modifyContext.getModItems()), ldapType);
						}
					}
				}
			}
		} else {
			next(modifyContext);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#move(org
	 * .apache.directory.server.core.api.interceptor.context.
	 * MoveOperationContext)
	 */
	@Override
	public void move(MoveOperationContext moveContext) throws LdapException {
		next(moveContext);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.apache.directory.server.core.api.interceptor.BaseInterceptor#
	 * moveAndRename(org.apache.directory.server.core.api.interceptor.context.
	 * MoveAndRenameOperationContext)
	 */
	@Override
	public void moveAndRename(MoveAndRenameOperationContext moveAndRenameContext) throws LdapException {
		next(moveAndRenameContext);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#rename(
	 * org.apache.directory.server.core.api.interceptor.context.
	 * RenameOperationContext)
	 */
	@Override
	public void rename(RenameOperationContext renameContext) throws LdapException {
		next(renameContext);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#search(
	 * org.apache.directory.server.core.api.interceptor.context.
	 * SearchOperationContext)
	 */
	@Override
	public synchronized EntryFilteringCursor search(SearchOperationContext searchContext) throws LdapException {
		logger.debug("Intercepted search");
		// making sure objectclass is sent across to avoid searches without
		logger.debug("search context " + searchContext.getFilter().toString());
		EntryCursor cursor;
		String mappings = null;
		String host = null;
		String currentTenantDN = null;
		String connString = null;
		String searchBase = searchContext.getDn().getName();
		logger.debug("search base is: " + searchContext.getDn().getName());

		if (StringUtils.containsIgnoreCase(searchBase, ",ou=tenants")){
			tenants = dsEngine.getAllTenants();
			if (tenants.isEmpty() && StringUtils.containsIgnoreCase(searchBase, ",ou=users")) {
				// Create the SearchRequest object
				SearchRequest req = new SearchRequestImpl();
				req.setScope(SearchScope.SUBTREE);
				req.addAttributes("*");
				req.setTimeLimit(0);
				req.setBase(new Dn("ou=tenants,o=emc"));
				req.setFilter("(objectClass=*)");
				Cursor<Entry> entries = dsEngine.getDsSession().getDirectoryService().getAdminSession().search(req);
				if (entries != null) {
					Iterator<Entry> it = entries.iterator();
					while (it.hasNext()) {
						Entry entry = it.next();
						String tenantToCheck = LdapCrudUtils.getTenantNameFromDn(entry.getDn().getName());
						tenants.put(tenantToCheck, entry);
						logger.debug("entry is " + entry);
					}
				} else
					logger.debug("entries are null");
			}
			
			String[] strings  = searchBase.split(",");
			if (strings.length>2){
			String tenantToCheck = LdapCrudUtils.getTenantNameFromDn(searchBase);
			System.out.println("tenant to check is " + tenantToCheck);

			if (tenantToCheck != null) {
				Entry tenantEntry = tenants.get(tenantToCheck);
				logger.debug(" in the loop, entry is: " + tenantEntry);
				if (tenantEntry.getDn().getName() != null) {
					currentTenantDN = tenantEntry.getDn().getName();
				}
				if (getMappings(tenantEntry) != null) {
					mappings = getMappings(tenantEntry);
				}
				if (tenantEntry.get("connectionString") != null) {
					connString = tenantEntry.get("connectionString").getString();
					logger.debug("connstionstring is " + tenantEntry.get("connectionString").getString());
					String hostname = dsEngine.getHostNameOrIP(tenantEntry.get("connectionString").getString());
					host = hostname;
					logger.debug("host is " + hostname);
				}
				String tenantId = null;
				if (tenantEntry.get("tenantId") != null) {
					tenantId = tenantEntry.get("tenantId").getString();
					logger.debug("tenantId is " + tenantId);
				}
				String ldapType = tenantEntry.get("ldapType").getString();
				String tenantUserSearchBase = null;
				if (tenantEntry.get(Constants.SOURCEUSERSDN) != null) {
					tenantUserSearchBase = tenantEntry.get(Constants.SOURCEUSERSDN).getString();
				}
				String sourceTenantDn = null;
				if (tenantEntry.get(Constants.SOURCETENANTDN) != null) {
					sourceTenantDn = tenantEntry.get(Constants.SOURCETENANTDN).getString();
				}
				if (searchBase.equalsIgnoreCase(currentTenantDN) && !StringUtils.containsIgnoreCase(searchBase, "ou=users")) {
	
					logger.debug("Searching the tenant level");
					if (searchContext.getScope().getScope() == 0) {
						return next(searchContext);
					}
					if (searchContext.getScope().getScope() == 1) {
						return next(searchContext);
					}
					if (searchContext.getScope().getScope() == 2) {
						logger.debug("subtree search");
						ProxyConnector connector = dsEngine.getConnectors().get(host);
						if (connector == null) {
							connector = instantiateConnector(connString);
						}
						try {

							return oneLevelSubTree(searchContext, mappings, searchBase, tenantEntry,
									tenantUserSearchBase, sourceTenantDn, connector, "ou=users", ldapType);

						} catch (CursorException e) {
							logger.debug(e.getMessage());
						}
					}
				
				}

				if (StringUtils.containsIgnoreCase(searchBase, USERSOU)){
					logger.debug("host is " + host);
					if (host != null) {
						try {
							ProxyConnector connector = dsEngine.getConnectors().get(host);
							if (connector == null) {
								connector = instantiateConnector(connString);
							}
							String firstPart = LdapCrudUtils.getFirstPartDn(searchBase);

							return oneLevelSubTree(searchContext, mappings, searchBase, tenantEntry,
									tenantUserSearchBase, sourceTenantDn, connector, firstPart,ldapType);

						} catch (Exception ex) {
							logger.debug(ex.getMessage());
							logger.debug("Falling through");
							return next(searchContext);
						}
					}
				}
			}
			}
		}
		return next(searchContext);
	}


	/**
	 * 
	 * Method performing the Users One Level and Users SubTree Searches
	 * 
	 * @param searchContext
	 * @param mappings
	 * @param searchBase
	 * @param tenantEntry
	 * @param tenantUserSearchBase
	 * @param connector
	 * @param firstPart
	 * @return
	 * @throws LdapInvalidDnException
	 * @throws CursorException
	 * @throws LdapInvalidAttributeValueException
	 */
	private EntryFilteringCursor oneLevelSubTree(SearchOperationContext searchContext, String mappings,
			String searchBase, Entry tenantEntry, String tenantUserSearchBase, String sourceTenantDn,
			ProxyConnector connector, String firstPart, String ldapType)
			throws LdapInvalidDnException, CursorException, LdapInvalidAttributeValueException {
		EntryCursor cursor = null;

		if (firstPart.equalsIgnoreCase(USERSOU)) {
			logger.debug("Searching the tenant's ou=users level");
			String prepend = null;
			String tenantName = null;
			String[] splits = searchBase.split(",");

			if (!StringUtils.containsIgnoreCase(searchBase, "ou=users")){
				prepend = "ou=users,".concat(splits[0]).concat(",").concat(sourceTenantDn);
				tenantName = splits[0];
				fullDn = splits[0].concat(",").concat(SEARCHBASESTR);
				sourceUserDn = USERSOU.concat(",").concat(tenantName).concat(",").concat(SOURCEDNSTR);
			} else {
				prepend = splits[0].concat(",").concat(splits[1]).concat(",").concat(sourceTenantDn);
				tenantName = splits[1];
				fullDn = splits[1].concat(",").concat(SEARCHBASESTR);
				sourceUserDn = USERSOU.concat(",").concat(tenantName).concat(",").concat(SOURCEDNSTR);
			}
			System.out.println("tenantUserSearchBasre is " + tenantUserSearchBase);
			searchContext.setDn(new Dn(tenantUserSearchBase));
			cursor = connector.searchByDn(searchContext);
			if (cursor == null)
				logger.debug("cursor is null");
			return new SourceEntryFilteringCursor(cursor, searchContext, dsEngine.getService().getSchemaManager(),
					new ArrayList<EntryFilter>() {
						{
							add(new AttributeTypeEntryFilter());
							add(new ReverseDNMappingEntryFilter((fullDn), tenantUserSearchBase, ldapType));
							add(new TenantIdFilter(tenantEntry.get("tenantId").getString()));
							
						}
					});
		} else {

			logger.debug("Searching the individual user's level");
			logger.debug("searchBase " +searchBase);
			String[] splits = searchBase.split(",");
			String fullDn = splits[2].concat(",").concat(SEARCHBASESTR);
		//	if (splits[0].contains("uid"))
			String connectorSearchBase = null;
			if (ldapType.equals("AD")){
				String splitsLowerCase = StringUtils.lowerCase(splits[0]);
				if (StringUtils.containsIgnoreCase(splitsLowerCase, "uid")){
					String  prefix = splitsLowerCase.replace("uid", "CN");
					connectorSearchBase = prefix.concat(",").concat(tenantUserSearchBase);
					logger.debug("updated connectorSearchBase " +connectorSearchBase);
				}
			} else {
			 connectorSearchBase  = splits[0].concat(",").concat(tenantUserSearchBase);
			}
			logger.debug("fullDn " +fullDn);
			logger.debug("connectorSearchBase " +connectorSearchBase);
			
			searchContext.setDn(new Dn(connectorSearchBase));
			cursor = connector.searchByDn(searchContext);
			
			return new SourceEntryFilteringCursor(cursor, searchContext, dsEngine.getService().getSchemaManager(),
					new ArrayList<EntryFilter>() {
						{
							add(new AttributeTypeEntryFilter());
							add(new ReverseDNMappingEntryFilter(fullDn, tenantUserSearchBase,ldapType));
							add(new TenantIdFilter(tenantEntry.get("tenantId").getString()));
						}
					});
		}
	}

	/**
	 * @param connString
	 * @return
	 * @throws LdapException
	 */
	private ProxyConnector instantiateConnector(String connString) throws LdapException {
		ProxyConnector connector;
		String[] ctrArray = connString.split(":");
		ConnectorInfo ctrInfo = new ConnectorInfo();
		ctrInfo.setHostname(ctrArray[0]);
		ctrInfo.setPort(Integer.parseInt(ctrArray[1]));
		ctrInfo.setUsername(ctrArray[2]);
		ctrInfo.setPassword(ctrArray[3]);
		connector = new DefaultProxyConnector(ctrInfo);
		return connector;
	}

	
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#unbind(
	 * org.apache.directory.server.core.api.interceptor.context.
	 * UnbindOperationContext)
	 */
	@Override
	public void unbind(UnbindOperationContext unbindContext) throws LdapException {
		next(unbindContext);
	}

	/**
	 * @param tenantDn
	 * @return
	 * @throws LdapException
	 */
	public synchronized Entry getUserEntry(String tenantDn) throws LdapException {
		Entry userOU = new DefaultEntry();
		userOU.setDn("ou=users" + tenantDn);
		userOU.add("objectClass", "organizationalUnit");
		userOU.add("objectClass", "top");
		return userOU;
	}

	/**
	 * @param user
	 * @param mappings
	 * @param postMappedDn
	 * @return
	 * @throws LdapException
	 */
	public Entry modifyUserEntry(User user, String mappings, String postMappedDn) throws LdapException {
		Entry transformedEntry = null;
		Entry entry = loadEntry(user);
		if (mappings != null) {
			transformedEntry = transformedEntry(mappings, entry, postMappedDn, false);
			List<String> list = LdapCrudUtils.getSourceTargetAttrs(mappings, true);
			Entry loopEntry = transformedEntry.clone();
			Iterator<Attribute> it = loopEntry.getAttributes().iterator();
			while (it.hasNext()) {
				Attribute attr = it.next();
				if (list.contains(attr.getId())) {
					transformedEntry.remove(attr.getId(), attr.getString());
				}
			}
		} else {
			transformedEntry = entry;
			transformedEntry.setDn(postMappedDn);
			addSourceObjClasses(transformedEntry);
		}
		return transformedEntry;
	}

	/**
	 * @param user
	 * @return
	 * @throws LdapInvalidDnException
	 * @throws LdapException
	 */
	public Entry loadEntry(User user) throws LdapInvalidDnException, LdapException {
		Entry entry = new DefaultEntry();
		entry.setDn(new Dn(user.getDistinguishedName()));
		entry.add("sn", user.getLastName());
		entry.add("cn", user.getFirstName());
		if (user.getEmail() != null && user.getEmail().length() > 0) {
			entry.add("mail", user.getEmail());
		}
		return entry;
	}

	/**
	 * @param tenantId
	 * @param sourceTenantDn
	 * @param sourceUsersDn
	 * @param attrsMap
	 * @param tenantName
	 * @return
	 */
	private Tenancy createTenantObject(String tenantId, String sourceTenantDn, String sourceUsersDn, String attrsMap,
			String tenantName) {
		Tenancy tenant = new Tenancy();
		tenant.setTenantName(tenantName);
		tenant.setSourceTenantDn(sourceTenantDn);
		tenant.setSourceUsersDn(sourceUsersDn);
		tenant.setAttrsMap(attrsMap);
		tenant.setTenantId(tenantId);
		return tenant;
	}

	/**
	 * @param host
	 * @param connectorInfo
	 * @throws LdapException
	 */
	private void preProcess(String host, ConnectorInfo connectorInfo) throws LdapException {
		ProxyConnector connector = dsEngine.bootstrapConnectionsForTenant(connectorInfo);
		if (connector != null) {
			dsEngine.getConnectors().put(host, connector);
		}
	}

	/**
	 * @param tenant
	 * @return
	 */
	protected Entry createEntryForSource(Tenancy tenant) {
		Entry newTenant = new DefaultEntry();
		try {
			newTenant.setDn("ou=" + tenant.getTenantName() + "," + tenant.getSourceTenantDn());
			newTenant.add("objectClass", "organizationalUnit");
			newTenant.add("objectClass", "top");
			newTenant.add("ou", tenant.getTenantName());
		} catch (LdapException e) {
			logger.debug("LdapException: " + e);
		}
		return newTenant;
	}

	/**
	 * @return
	 */
	protected boolean isExtConnections() {
		Map<String, ProxyConnector> extConnections = tenant.getExtConnections();
		if (extConnections != null && extConnections.size() > 0) {
			return true;
		}
		return false;
	}

	/**
	 * @param origEntry
	 * @param extConnections
	 * @throws LdapException
	 */
	protected void addExternal(Entry origEntry, Map<String, ProxyConnector> extConnections) throws LdapException {
		for (Map.Entry<String, ProxyConnector> entry : extConnections.entrySet()) {
			ProxyConnector connector = entry.getValue();
			logger.info("connector name is " + entry.getKey());
			Entry modifiedEntry = tenant.transformEntryExternal(origEntry);
			if (modifiedEntry != null) {
				connector.add(modifiedEntry, getConfig().isTransparentProxy());
			}

		}
	}

	/**
	 * @param tenant
	 * @param host
	 * @param sourceEntry
	 * @throws LdapException
	 */
	private void processSourceInsert(Tenancy tenant, String host, Entry sourceEntry) throws LdapException {
		if (tenant.getAttrsMap() == null || tenant.getAttrsMap().length() == 0) {
			dsEngine.getConnectors().get(host).add(sourceEntry, true);
		} else {
			dsEngine.getConnectors().get(host).add(sourceEntry, false);
		}
		Entry userOUSource = dsEngine.getEmbeddedConnector().getUserEntry(sourceEntry.getDn().toString());
		dsEngine.getConnectors().get(host).addEntry(userOUSource);
	}

	/**
	 * @return
	 */
	public LdapNetworkConnection getEmbeddedConnection() {
		return embeddedConnection;
	}

	/**
	 * @param embeddedConnection
	 */
	public void setEmbeddedConnection(LdapNetworkConnection embeddedConnection) {
		this.embeddedConnection = embeddedConnection;
	}

	/**
	 * @return
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
	 * @return
	 */
	public Tenant getTenant() {
		return tenant;
	}

	/**
	 * @param tenant
	 */
	public void setTenant(Tenant tenant) {
		this.tenant = tenant;
	}

	/**
	 * @return
	 */
	public Map<String, ProxyConnector> getConnectorMap() {
		return connectorMap;
	}

	/**
	 * @param connectorMap
	 */
	public void setConnectorMap(final Map<String, ProxyConnector> connectorMap) {
		this.connectorMap = connectorMap;
	}

	/**
	 * @return
	 */
	public AppConfig getConfig() {
		return config;
	}

	/**
	 * @param config
	 */
	public void setConfig(AppConfig config) {
		this.config = config;
	}

	/**
	 * @return
	 */
	public DSEngine getEngine() {
		return dsEngine;
	}

	/**
	 * @param engine
	 */
	public void setEngine(DSEngine engine) {
		this.dsEngine = engine;
	}

	/**
	 * @param entry
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	private String getMappings(Entry entry) throws LdapInvalidAttributeValueException {
		if (entry.containsAttribute(Enums.CustomAttributes.ATTRIBUTEMAP.toString()))
			return entry.get(Enums.CustomAttributes.ATTRIBUTEMAP.toString()).getString();
		else
			return null;
	}

	/**
	 * @param entry
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	private String getHostName(Entry entry) throws LdapInvalidAttributeValueException {
		return dsEngine.getHostNameOrIP(entry.get(Constants.CONNECTIONSTRING).getString());
	}
	
	/**
	 * @param entry
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	private String getPort(Entry entry) throws LdapInvalidAttributeValueException {
		return dsEngine.getPort(entry.get(Constants.CONNECTIONSTRING).getString());
	}

	/**
	 * @param mappings
	 * @param sourceUserNode
	 * @param userName
	 * @return
	 */
	protected String getPostMappedDn(String mappings, String sourceUserNode, String userName) {
		String postMappedDn;
		if (userName.equals("users"))
			return sourceUserNode;
		if (mappings != null && mappings.trim().length() > 0) {
			postMappedDn = LdapCrudUtils.createDnForTranslation(userName, sourceUserNode, mappings);
		} else {
			postMappedDn = "uid=".concat(userName).concat(",").concat(sourceUserNode);
		}
		return postMappedDn;
	}

	protected String rolodexDnToSource(String mappings, String sourceUserNode, String firstPart) {
		String postMappedDn;
		if (mappings != null && mappings.trim().length() > 0) {
			postMappedDn = LdapCrudUtils.createDnForTranslation(LdapCrudUtils.getUserNameFromDn(firstPart),
					sourceUserNode, mappings);
		} else {
			postMappedDn = firstPart.concat(",").concat(sourceUserNode);
		}
		return postMappedDn;
	}

	/**
	 * @param usrPwd
	 * @param user
	 * @param mappings
	 * @param postMappedDn
	 * @param connector
	 * @throws LdapException
	 */
	protected void createAndAddEntrySource(String usrPwd, User user, String mappings, String postMappedDn,
			ProxyConnector connector, String ldapType) throws LdapException {
		if (connector != null) {
			// usrPwd = getTemppwd();
			Entry userEntry = createUserEntrySource(user, postMappedDn, usrPwd, ldapType);
			System.out.println("userentry is " + userEntry);
			if (mappings != null) {
				Entry updatedEntry = transformedEntry(mappings, userEntry, postMappedDn, false);
				System.out.println("updatedEntry: " + updatedEntry);
				connector.addEntry(updatedEntry);
			} else {
				logger.info("userentry added to connector " + userEntry);
				connector.addEntry(userEntry);
			}
		}
	}

	/**
	 * @param user
	 * @param postMappedDn
	 * @param tempPwd
	 * @return
	 * @throws LdapException
	 */
	public Entry createUserEntrySource(User user, String postMappedDn, String tempPwd, String ldapType) throws LdapException {
		Entry entry = new DefaultEntry();
		entry.setDn(postMappedDn);
		entry.add("sn", user.getLastName());
		if (ldapType.equalsIgnoreCase("AD")){
		String firstPart[] = postMappedDn.split(",");
		String splitFirstPart[] = firstPart[0].split("=");
		entry.add("cn", splitFirstPart[1]);
		} else
		 entry.add("cn", user.getFirstName());
		if (user.getEmail() != null && user.getEmail().length() > 0) {
			entry.add("mail", user.getEmail());
		}
		if (user.isSourcePwdUnicode()) {
			entry.add(UNICODEPASSWORD, tempPwd);
		} else
			entry.add(USERPASSWORD, LdapCrudUtils.generateSSHA(tempPwd));
		
		addSourceObjClasses(entry);
		return entry;
	}

//	/**
//	 * @param postMappedDn
//	 * @return
//	 */
//	protected String convertUidToUserPrincipal(String postMappedDn) {
//		return postMappedDn.replace("uid", "userPrincipalName");
//	}

	/**
	 * @param transformedEntry
	 * @throws LdapException
	 */
	private void addSourceObjClasses(Entry transformedEntry) throws LdapException {
		transformedEntry.add("objectClass", "inetOrgPerson", "organizationalPerson", "person", "top");
	}

	/**
	 * @param mapping
	 * @param baseEntry
	 * @param postmappedDn
	 * @param isReverse
	 * @return
	 * @throws LdapException
	 */
	protected Entry transformedEntry(String mapping, Entry baseEntry, String postmappedDn, boolean isReverse)
			throws LdapException {
		Entry transformedEntry = new DefaultEntry();
		transformedEntry.setDn(postmappedDn);
		if (mapping.contains(",")) {
			String[] map = mapping.split(",");
			for (String assignment : map) {
				replaceAttrs(assignment, baseEntry, transformedEntry, isReverse);
			}
		} else
			replaceAttrs(mapping, baseEntry, transformedEntry, isReverse);
		List<String> list = LdapCrudUtils.getSourceTargetAttrs(mapping, true);
		Entry loopEntry = transformedEntry.clone();
		Iterator<Attribute> it = loopEntry.getAttributes().iterator();
		while (it.hasNext()) {
			Attribute attr = it.next();
			if (list.contains(attr.getId())) {
				transformedEntry.remove(attr.getId(), attr.getString());
			}
		}
		transformedEntry.add("objectClass", "inetOrgPerson", "organizationalPerson", "person", "top");
		return transformedEntry;
	}

	/**
	 * @param mapping
	 * @param baseEntry
	 * @param transformedEntry
	 * @param isReverse
	 */
	private void replaceAttrs(String mapping, Entry baseEntry, Entry transformedEntry, boolean isReverse) {
		try {
			Iterator<Attribute> attrs = baseEntry.getAttributes().iterator();
			while (attrs.hasNext()) {
				Attribute attr = attrs.next();
				if (mapping.contains(attr.getId())) {
					String[] map = mapping.split("=");
					if (!isReverse) {
						transformedEntry.add(map[1], attr.getString());
					} else
						logger.info("reverse attr " + map[0]);
					transformedEntry.add(map[0], attr.getString().toString());
				} else {
					System.out.println(attr.getId().toString() + " , " + attr.getString().toString());
					if (!attr.getId().toString().equals("objectclass"))
						transformedEntry.add(attr.getId().toString(), attr.getString().toString());
				}
			}
			logger.info("transformed entry is " + transformedEntry);
		} catch (Exception e) {
			logger.info("exception " + e);
		}
	}

}