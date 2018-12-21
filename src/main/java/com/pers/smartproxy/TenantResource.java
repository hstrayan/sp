package com.pers.smartproxy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.representations.ConnectorInfo;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.pers.smartproxy.representations.Tenancy;
import com.pers.smartproxy.services.DSEngine;
import com.pers.smartproxy.utils.Constants;

@Path("auth/v1/tenant")
@Produces(MediaType.APPLICATION_JSON)
public class TenantResource {

	final Logger logger = LoggerFactory.getLogger(TenantResource.class);
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
	public TenantResource() {
		// no-args
	}

	/**
	 * Constructor
	 * 
	 * @param dsEngine
	 * @param configuration
	 */
	public TenantResource(final DSEngine dsEngine, final AppConfig configuration) {
		this.configuration = configuration;
		this.dsEngine = dsEngine;
	}

	/**
	 * @param tenantID
	 * @return
	 */
	@GET
	@Path("/all")
	public Response retrieveAllTenants() {
		List<Tenancy> tenants = getAllTenants();
		if (!tenants.isEmpty()) {
			return Response.ok(tenants.toArray()).build();
		} else
			return Response.status(Response.Status.NOT_FOUND).entity("No tenants found").build();
	}

	/**
	 * @param tenantID
	 * @return
	 */
	@GET
	public Response lookupTenantById(@QueryParam("id") Optional<String> tenantID) {
		// tenantId not present
		if (!tenantID.isPresent()) {
			return Response.status(Response.Status.NOT_FOUND).entity("Tenant Id required").build();
		}
		// tenantID is present
		Entry entry = null;
		EntryCursor entryCursor = null;
		try {
			entryCursor = dsEngine.getEmbeddedConnector().searchTenantByAttr(Constants.TENANTID, tenantID.get());
			while (entryCursor.next()) {
				entry = entryCursor.get();
				return Response.ok(getTenantResponse(entry)).build();
			}
		} catch (LdapException | CursorException ex) {
			return Response.status(Response.Status.NOT_FOUND).build();
		} finally {
			try {
				entryCursor.close();
			} catch (IOException e) {
				logger.debug(" exception " + e);
			}
		}
		return Response.status(Response.Status.NOT_FOUND).entity("Tenant not found using Tenant ID").build();
	}

	/**
	 * @param entry
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	protected Tenancy getTenantResponse(Entry entry) throws LdapInvalidAttributeValueException {
		Tenancy tenant = new Tenancy();
		if (entry.getDn() != null) {
			tenant.setTenantName(entry.getDn().getName());
		}
		Attribute tenantId = entry.get(Constants.TENANTID);
		if (tenantId != null) {
			tenant.setTenantId(tenantId.getString());
		}
		Attribute sourceTenantDn = entry.get(Constants.SOURCETENANTDN);
		if (sourceTenantDn != null) {
			tenant.setSourceTenantDn(sourceTenantDn.getString());
		}
		Attribute sourceUsersDn = entry.get(Constants.SOURCEUSERSDN);
		if (sourceUsersDn != null) {
			tenant.setSourceUsersDn(sourceUsersDn.getString());
		}
		Attribute attrsMap = entry.get(Constants.ATTRSMAP);
		if (attrsMap != null) {
			tenant.setAttrsMap(attrsMap.getString());
		}
		Attribute connectionString = entry.get(Constants.CONNECTIONSTRING);
		if (connectionString != null) {
			tenant.setConnectionString(connectionString.getString());
		}
		Attribute ldapType = entry.get(Constants.LDAPTYPE);
		if (ldapType != null) {
			tenant.setConnectionString(ldapType.getString());
		}
		Attribute readOnly = entry.get(Constants.READONLY);
		if (readOnly != null) {
			if (readOnly.getString().equals("true")) {
				tenant.setReadOnly(true);
			} else
				tenant.setReadOnly(false);
		}
		return tenant;
	}

	/**
	 * @param tenant
	 * @return Response
	 */
	@POST
	public Response addNewTenant(Tenancy tenant) {
		validate(tenant);
		try {
			Entry entry = dsEngine.getEmbeddedConnector().getEntryFromTenantObj(tenant);
			dsEngine.getEmbeddedConnector().addTenantViaIntr(entry);
			// add OU
			String ouDn = "ou=users," + entry.getDn().getName();
			Entry ouEntry = new DefaultEntry(new Dn(ouDn), "objectClass: top", "objectClass: organizationalUnit");
			dsEngine.getEmbeddedConnector().addSubTenantOUs(ouEntry);
			Entry searchEntry = dsEngine.getEmbeddedConnector().lookUpTenantByDn(entry.getDn().getName());
			Tenancy addedTenant = getTenantResponse(searchEntry);
			return Response.status(Response.Status.ACCEPTED).entity(addedTenant).build();
		} catch (Exception e) {
			return Response.status(Response.Status.EXPECTATION_FAILED).entity(e.getMessage()).build();
		}

	}

	/**
	 * @param tenantID
	 * @return
	 */
	@DELETE
	@Path("/{id}")
	public Response deleteTenant(@PathParam("id") String dn) {
		if (dn == null)
			return Response.status(Response.Status.BAD_REQUEST).build();
		try {
			if (dsEngine.getEmbeddedConnector().deleteByDn(new Dn(dn))) {
				return Response.status(Response.Status.OK).build();
			}

		} catch (LdapException | UnsupportedOperationException e) {
			logger.debug("Exception:" + e);
			return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
		}
		return Response.status(Response.Status.BAD_REQUEST).build();
	}

	/**
	 * @param tenantID
	 * @param tenant
	 * @return
	 */
	@PUT
	@Path("/{id}")
	public Response updateTenant(@PathParam("id") String tenantID, Tenancy tenant) {
		if (tenantID == null)
			return Response.status(Response.Status.BAD_REQUEST).build();
		if (tenant == null)
			return Response.status(Response.Status.BAD_REQUEST).build();
		if (tenant.getAttrsMap().isEmpty())
			tenant.setAttrsMap(" ");
		try {
			EntryCursor entryCursor = dsEngine.getEmbeddedConnector().searchTenantByAttr(Constants.TENANTID, tenantID);
			if (entryCursor.next() == true) {
				String origDn = entryCursor.get().getDn().getName();
				if (dsEngine.getEmbeddedConnector().modifyTenant(origDn, tenant))
					return Response.status(Response.Status.ACCEPTED).entity(tenant).build();
			} else
				return Response.status(Response.Status.EXPECTATION_FAILED).entity("Incorrect Tenant ID used").build();
		} catch (CursorException | LdapException | UnsupportedOperationException e) {
			logger.debug("Exception:" + e);
			return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
		}
		return Response.status(Response.Status.EXPECTATION_FAILED).entity("failed modifying tenant").build();
	}

	/**
	 * @param tenant
	 * @return
	 */
	@PUT
	public Response changeTenantNameLocal(Tenancy tenant) {
		if (tenant == null)
			return Response.status(Response.Status.BAD_REQUEST).build();
		try {
			EntryCursor entryCursor = dsEngine.getEmbeddedConnector().searchTenantByAttr(Constants.TENANTID,
					tenant.getTenantId());
			if (entryCursor.next() == true) {
				String origDn = entryCursor.get().getDn().getName();
				Rdn modifiedName = new Rdn("ou=" + tenant.getTenantName());
				dsEngine.getEmbeddedConnector().getPool().getConnection().rename(new Dn(origDn), modifiedName);
			}
		} catch (Exception e) {
			return Response.status(Response.Status.EXPECTATION_FAILED).entity("failed renaming tenant").build();
		}
		return Response.status(Response.Status.ACCEPTED).build();
	}

	/**
	 * Get All tenants
	 * 
	 * @return List<Tenancy>
	 */
	protected List<Tenancy> getAllTenants() {
		List<Tenancy> tenants = new ArrayList<Tenancy>();
		Entry entry = null;
		EntryCursor entryCursor = null;
		try {
			entryCursor = dsEngine.getEmbeddedConnector().retrieveAllTenants();
			while (entryCursor.next()) {
				entry = entryCursor.get();
				logger.debug("Entry:" + entry);
				Tenancy tenant = getTenantResponse(entry);
				tenants.add(tenant);
			}
			return tenants;
		} catch (LdapException | CursorException ex) {
			logger.debug("Exception: " + ex);
			return null;
		} finally {
			try {
				entryCursor.close();
			} catch (IOException e) {
				logger.debug(" exception " + e);
			}
		}
	}
	
	/**
	 * @param host
	 * @param connectorInfo
	 * @throws LdapException
	 */
	private void preProcess(String host, ConnectorInfo connectorInfo) throws LdapException {
		logger.info("....preProcess. 1....");
		ProxyConnector connector = getDsEngine().bootstrapConnectionsForTenant(connectorInfo);
		logger.info("....preProcess.....");
		if (connector != null) {
			logger.info("....preProcess.....");
			getDsEngine().getConnectors().put(host, connector);
		}
	}

	/**
	 * @param entry
	 * @return
	 * @throws LdapException
	 */
	private String processEmbeddedInsert(Entry entry) throws LdapException {
		String tenantId = null;
	//	try{
		tenantId = dsEngine.getEmbeddedConnector().addTenant(entry);
		// add ou=users
		Entry userOU = dsEngine.getEmbeddedConnector().getUserEntry(entry.getDn().toString());
		dsEngine.getEmbeddedConnector().addSubTenantOUs(userOU);
		// add OU=groups
		Entry groupOU = dsEngine.getEmbeddedConnector().getGroupEntry(entry.getDn().toString());
		dsEngine.getEmbeddedConnector().addSubTenantOUs(groupOU);
//		}catch(Exception e){
//			logger.debug("Exception: " + e);
//		}
		return tenantId;
	}

	/**
	 * @param tenant
	 * @param host
	 * @param sourceEntry
	 * @throws LdapException
	 */
	private void processSourceInsert(Tenancy tenant, String host, Entry sourceEntry) throws LdapException {
		if (tenant.getAttrsMap().length() == 0) {
			getDsEngine().getConnectors().get(host).add(sourceEntry, true);
		} else {
			getDsEngine().getConnectors().get(host).add(sourceEntry, false);
		}
		Entry userOUSource = dsEngine.getEmbeddedConnector().getUserEntry(sourceEntry.getDn().toString());
		getDsEngine().getConnectors().get(host).addEntry(userOUSource);
	}

	/**
	 * @param tenant
	 * @return Response
	 */
	protected Response validate(Tenancy tenant) {
		if (tenant == null)
			return Response.status(Response.Status.BAD_REQUEST).build();
		if (tenant.getTenantName() == null || tenant.getTenantName().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'tenant name' is required").build();
		if (tenant.getSourceTenantDn() == null || tenant.getSourceTenantDn().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'source dn' is required").build();
		if (tenant.getSourceUsersDn() == null || tenant.getSourceUsersDn().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'users dn' is required").build();
		if (tenant.getConnectionString() == null || tenant.getConnectionString().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'connection string' is required").build();
		if (tenant.getLdapType() == null || tenant.getLdapType().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'Ldap Type' is required").build();
		if (tenant.isReadOnly())
			return Response.status(Response.Status.BAD_REQUEST).entity("'read-only flag' is required").build();
		if (tenant.getResourceSetID() == null || tenant.getResourceSetID().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'ResourceSet ID' is required").build();
		return null;
	}

	/**
	 * @param tenant
	 * @return
	 */
	protected Entry createEntryForSource(Tenancy tenant) {
		Entry newTenant = new DefaultEntry();
		logger.debug("source dn is " + "ou=" + tenant.getTenantName() + "," + tenant.getSourceTenantDn());
		try {
			newTenant.setDn("ou=" + tenant.getTenantName() + "," + tenant.getSourceTenantDn());
			newTenant.add("objectClass", "organizationalUnit");
			newTenant.add("objectClass", "top");
			newTenant.add("ou", tenant.getTenantName());
			logger.debug("entry is " + newTenant);
		} catch (LdapException e) {
			logger.debug("LdapException: " + e);
		}
		return newTenant;
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

}
