package com.pers.smartproxy;

import java.util.Iterator;
import java.util.List;

import javax.ws.rs.Consumes;
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

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.pers.smartproxy.connectors.ProxyConnector;
import com.pers.smartproxy.representations.User;
import com.pers.smartproxy.services.DSEngine;
import com.pers.smartproxy.utils.Constants;
import com.pers.smartproxy.utils.LdapCrudUtils;
import com.pers.smartproxy.utils.RandomStringGenerator;

/**
 * @author sathyh2
 * 
 *         User Tenant CRUD operations - adding to source/embedded LDAP trees
 *
 */
@Path("auth/v1/user")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserTenantResource {

	final Logger logger = LoggerFactory.getLogger(UserTenantResource.class);

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
	public UserTenantResource() {
		// no-args
	}

	public UserTenantResource(final DSEngine dsEngine, final AppConfig configuration) {
		this.configuration = configuration;
		this.dsEngine = dsEngine;
	}

	/**
	 * @param userID
	 * @return
	 */
	@GET
	@Path("{id}")
	public Response searchUserByUserId(@PathParam("id") String userID) {
		if (userID == null)
			return Response.status(Response.Status.BAD_REQUEST).entity("UserID not specified").build();
		try {
			User user = dsEngine.getEmbeddedConnector().lookUpUserByUID(userID);
			if (user != null)
				return Response.ok(user).build();
			else
				return Response.status(Response.Status.NOT_FOUND).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
	}

	/**
	 * @param dn
	 * @return
	 */
	@GET
	public Response searchUserByDn(@QueryParam("dn") Optional<String> dn) {
		if (dn == null)
			return Response.status(Response.Status.BAD_REQUEST).entity("DN not specified").build();
		try {
			User user = dsEngine.getEmbeddedConnector().lookUpUserByDn(dn.get());
			if (user != null)
				return Response.ok(user).build();
			else
				return Response.status(Response.Status.NOT_FOUND).build();
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
	}

	@Path("/searchSrcByDn/{dn}")
	@GET
	public Response searchUserByUserDN(@PathParam("dn") String userDn) {
		if (userDn == null)
			return Response.status(Response.Status.BAD_REQUEST).entity("UserID not specified").build();
		try {
			logger.info("user dn " + userDn);
			User user = dsEngine.getEmbeddedConnector().lookUpUserByDn(userDn);
			if (user != null)
				return Response.ok(user).build();
			else {
				// go to source
				String tenantName = LdapCrudUtils.getTenantNameFromDn(userDn);
				EntryCursor cursor = dsEngine.getEmbeddedConnector().searchTenantByAttr("ou", tenantName);
				if (cursor.next()) {
					Entry entry = cursor.get();
					String mappings = getMappings(entry);
					String host = getHostName(entry);
					String userName = LdapCrudUtils.getUserNameFromDn(userDn);
					String postMappedDn = getPostMappedDn(mappings, entry.get("sourceUsersDn").getString(), userName);
					if (host != null) {
						ProxyConnector connector = getDsEngine().getConnectors().get(host);
						if (connector != null) {
							Entry searchEntry = connector.searchUser(postMappedDn);
							logger.info("retrieved entry is " + searchEntry);
							System.out.println("search entry is " + searchEntry);
							if (searchEntry != null) {
								if (mappings != null && mappings.trim().length() > 0) {
									Entry transformedEntry = transformedEntrySearch(mappings, searchEntry, postMappedDn,
											true);

									System.out.println("transformedEntry entry is " + transformedEntry);
									User userEntity = loadUser(transformedEntry);
									return Response.status(Response.Status.OK).entity(userEntity).build();
								} else {
									User userEntity = loadUser(searchEntry);
									return Response.status(Response.Status.OK).entity(userEntity).build();
								}
							}
						}
					}
				}

			}
		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
		return Response.status(Response.Status.NOT_FOUND).build();
	}

	/**
	 * @param userID
	 * @return
	 */
	@DELETE
	@Path("/{userid}")
	public Response deleteUserByUserId(@PathParam("userid") String userID) {
		if (userID == null)
			return Response.status(Response.Status.BAD_REQUEST).build();
		try {
			if (dsEngine.getEmbeddedConnector().deleteUserByUserId(userID)) {
				return Response.ok("user deleted").build();
			} else
				return Response.status(Response.Status.NOT_FOUND).build();

		} catch (Exception e) {
			return Response.status(Response.Status.NOT_FOUND).build();
		}
	}

	/**
	 * Delete User
	 * 
	 * @param user
	 * @return Response
	 */
	@POST
	@Path("/deleteByUser")
	public Response deleteUser(User user) {
		validateUser(user);
		EntryCursor cursor = doesTenantExistLocally(user);
		if (cursor == null)
			return Response.status(Response.Status.NOT_FOUND)
					.entity("Could not find Tenant with ID '" + user.getTenantID() + "'").build();
		// embedded, remove source deletion. it is handled by interceptors
		try {
			dsEngine.getEmbeddedConnector().deleteByDn(new Dn(user.getDistinguishedName()));
		} catch (Exception e) {
			return Response.status(Response.Status.EXPECTATION_FAILED).entity(e.getMessage()).build();
		}
		return Response.status(Response.Status.ACCEPTED)
				.entity("successful delete of User DN: " + user.getDistinguishedName()).build();
	}

	/**
	 * @param User
	 * @return Response
	 */
	@POST
	public Response addUser(User user) {
		validateUser(user);
		User addeduser = null;
		try {
			Entry userEntry = new DefaultEntry();
			userEntry.setDn(new Dn(user.getDistinguishedName()));
			userEntry.add("cn", user.getFirstName());
			userEntry.add("sn", user.getLastName());
			userEntry.add("mail", user.getEmail());
			userEntry.add("tempPwd", getTemppwd());
			userEntry.add("tenantId", user.getTenantID());
			userEntry.add("objectClass", "tenancy", "inetOrgPerson", "organizationalPerson", "person", "top");
			dsEngine.getEmbeddedConnector().addUser(userEntry);
			addeduser = loadUser(userEntry);
		} catch (Exception e) {
			return Response.status(Response.Status.EXPECTATION_FAILED).entity("Problem Adding User to Source").build();
		}
		return Response.status(Response.Status.CREATED).entity(addeduser).build();
	}

	/**
	 * @param User
	 * @return Response
	 */
	@PUT
	public Response modifyUser(User user) {
		validateUser(user);
		EntryCursor cursor = doesTenantExistLocally(user);
		if (cursor == null)
			return Response.status(Response.Status.NOT_FOUND)
					.entity("Could not find Tenant with ID '" + user.getTenantID() + "'").build();
		// do we need to modify source?
		try {
			ModifyRequest modRequest = new ModifyRequestImpl();
			modRequest.setName(new Dn(user.getDistinguishedName()));
			Modification modCn = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "cn",
					user.getFirstName());
			Modification modSn = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "sn",
					user.getLastName());
			Modification modMail = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "mail",
					user.getEmail());
			modRequest.addModification(modCn);
			modRequest.addModification(modSn);
			modRequest.addModification(modMail);
			dsEngine.getEmbeddedConnector().modifyUser(modRequest);
		} catch (Exception e) {
			return Response.status(Response.Status.EXPECTATION_FAILED).entity(e.getMessage()).build();
		}
		return Response.status(Response.Status.ACCEPTED)
				.entity("Successful Modification of User Attributes for User DN: " + user.getDistinguishedName())
				.build();
	}

	/**
	 * @param dn
	 * @param oldPwd
	 * @param newPwd
	 * @return
	 * @throws LdapException
	 * @throws CursorException
	 */
	@POST
	@Path("/password/change")
	public Response changePassword(User user) throws LdapException, CursorException {
		if (user.getTenantID() != null && user.getUserName() != null && user.getPassword() != null
				&& user.getNewPassword() != null) {
			EntryCursor cursor = doesTenantExistLocally(user);
			if (cursor.next()) {
				Entry entry = cursor.get();
				String mappings = getMappings(entry);
				String ldapType = entry.get("ldapType").getString();
				if (ldapType.equalsIgnoreCase("AD"))
					user.setSourcePwdUnicode(true);
				String host = getHostName(entry);
				String postMappedDn = getPostMappedDn(mappings, entry.get("sourceUsersDn").getString(),
						user.getUserName());
				if (host != null) {
					ProxyConnector connector = getDsEngine().getConnectors().get(host);
					if (connector != null) {
						if (!connector.changePassword(postMappedDn, user.getPassword(), user.getNewPassword(),
								user.isSourcePwdUnicode())) {
							return Response.status(Response.Status.EXPECTATION_FAILED)
									.entity("Invalid Input Parameters").build();
						}
					}
				}
			}
		} else
			return Response.status(Response.Status.BAD_REQUEST).build();

		return Response.status(Response.Status.ACCEPTED).build();

	}

	/**
	 * @param user
	 * @return
	 * @throws LdapException
	 * @throws CursorException
	 */
	@POST
	@Path("/password/reset")
	public Response resetPassword(User user) throws LdapException, CursorException {
		if (user.getTenantID() != null && user.getUserName() != null) {
			EntryCursor cursor = doesTenantExistLocally(user);
			if (cursor.next()) {
				Entry entry = cursor.get();
				String mappings = getMappings(entry);
				String ldapType = entry.get("ldapType").getString();
				if (ldapType.equalsIgnoreCase("AD"))
					user.setSourcePwdUnicode(true);
				String host = getHostName(entry);
				String postMappedDn = getPostMappedDn(mappings, entry.get("sourceUsersDn").getString(),
						user.getUserName());
				if (host != null) {
					ProxyConnector connector = getDsEngine().getConnectors().get(host);
					if (connector != null) {
						String tempPwd = connector.resetPassword(postMappedDn, getTemppwd(), user.isSourcePwdUnicode());
						if (tempPwd != null) {
							user.setTempPassword(tempPwd);
						} else
							return Response.status(Response.Status.EXPECTATION_FAILED)
									.entity("Invalid Input Parameters").build();
					}
				}
			}
		}
		return Response.status(Response.Status.OK).entity(user).build();
	}

	/**
	 * @param user
	 * @param usrPwd
	 * @return
	 * @throws LdapException
	 */
	protected User createAndAddEntryLocal(User user, String usrPwd) throws LdapException {
		Entry newUserEntry = createUserEntry(user, usrPwd);
		newUserEntry.add("tenantId", user.getTenantID());
		newUserEntry.add("objectClass", "tenancy");
		dsEngine.getEmbeddedConnector().addUser(newUserEntry);
		User newUser = dsEngine.getEmbeddedConnector().lookUpUserByDn(user.getDistinguishedName());
		return newUser;
	}

	/**
	 * @param user
	 * @param mappings
	 * @param postMappedDn
	 * @param connector
	 * @return
	 * @throws LdapException
	 */
	protected String createAndAddEntrySource(User user, String mappings, String postMappedDn, ProxyConnector connector)
			throws LdapException {
		String usrPwd = null;
		if (connector != null) {
			usrPwd = getTemppwd();
			Entry userEntry = createUserEntrySource(user, postMappedDn, usrPwd);
			logger.info("userentry is " + userEntry);
			if (mappings != null) {
				Entry updatedEntry = transformedEntry(mappings, userEntry, postMappedDn, false);
				connector.addEntry(updatedEntry);
			} else {
				logger.info("userentry added to connector " + userEntry);
				connector.addEntry(userEntry);
			}
		}
		return usrPwd;
	}

	/**
	 * @param entry
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	private String getMappings(Entry entry) throws LdapInvalidAttributeValueException {
		return entry.get("attrsMap").getString();
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
	 * @param user
	 * @return
	 */
	private EntryCursor doesTenantExistLocally(User user) {
		return dsEngine.getEmbeddedConnector().searchTenantByAttr(Constants.TENANTID, user.getTenantID());
	}

	/**
	 * @return String
	 */
	private String getTemppwd() {
		return RandomStringGenerator.generateRandomString(48);
	}

	/**
	 * @param user
	 * @return
	 */
	protected Response validateUser(User user) {
		if (user == null)
			return Response.status(Response.Status.BAD_REQUEST).build();
		if (user.getDistinguishedName() == null || user.getDistinguishedName().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'User DN' is required").build();
		if (user.getFirstName() == null || user.getFirstName().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'User FirstName' is required").build();
		if (user.getLastName() == null || user.getLastName().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'User LastName' is required").build();
		if (user.getTenantID() == null || user.getTenantID().length() == 0)
			return Response.status(Response.Status.BAD_REQUEST).entity("'Tenant ID' is required").build();
		return null;
	}

	/**
	 * @param mappings
	 * @param sourceUserNode
	 * @param userName
	 * @return String
	 */
	protected String getPostMappedDn(String mappings, String sourceUserNode, String userName) {
		String postMappedDn;
		if (mappings != null && mappings.trim().length() > 0) {
			postMappedDn = LdapCrudUtils.createDnForTranslation(userName, sourceUserNode, mappings);
		} else {
			postMappedDn = "uid=".concat(userName).concat(",").concat(sourceUserNode);
		}
		return postMappedDn;
	}

	/**
	 * @param entry
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	protected boolean isAddToSource(Entry entry) throws LdapInvalidAttributeValueException {
		String readOnly = entry.get("readOnly").getString();
		String hasSource = entry.get("hasSource").getString();
		if (readOnly.equals("false") && hasSource.equals("true")) {
			return true;
		}
		return false;
	}

	/**
	 * @param mapping
	 * @param baseEntry
	 * @return
	 * @throws LdapInvalidAttributeValueException
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
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 * @throws LdapException
	 */
	protected Entry transformedEntrySearch(String mapping, Entry baseEntry, String postmappedDn, boolean isReverse)
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
		List<String> list = LdapCrudUtils.getSourceTargetAttrs(mapping, false);
		Entry loopEntry = transformedEntry.clone();
		transformedEntry.add("objectClass", "inetOrgPerson", "organizationalPerson", "person", "top");
		return transformedEntry;
	}

	/**
	 * @param mapping
	 * @param baseEntry
	 * @param transformedEntry
	 * @throws LdapException
	 * @throws LdapInvalidAttributeValueException
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
						System.out.println("reverse attr " + map[0]);
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

	/**
	 * @param user
	 * @return
	 * @throws LdapException
	 */
	public Entry createUserEntrySource(User user, String postMappedDn, String tempPwd) throws LdapException {
		Entry entry = new DefaultEntry();
		entry.setDn(postMappedDn);
		entry.add("sn", user.getLastName());
		entry.add("cn", user.getFirstName());
		if (user.getEmail() != null && user.getEmail().length() > 0) {
			entry.add("mail", user.getEmail());
		}
		if (user.isSourcePwdUnicode()) {
			entry.add("unicodePassword", LdapCrudUtils.generateSSHA(tempPwd));
		} else
			entry.add("userPassword", LdapCrudUtils.generateSSHA(tempPwd));
		addSourceObjClasses(entry);
		return entry;
	}

	/**
	 * @param user
	 * @return
	 * @throws LdapException
	 */
	public Entry createUserEntry(User user, String tempPwd) throws LdapException {
		Entry entry = loadEntry(user);
		if (user.isSourcePwdUnicode()) {
			entry.add("unicodePassword", LdapCrudUtils.generateSSHA(tempPwd));
		} else
			entry.add("userPassword", LdapCrudUtils.generateSSHA(tempPwd));
		addSourceObjClasses(entry);
		return entry;
	}

	/**
	 * @param transformedEntry
	 * @throws LdapException
	 */
	private void addSourceObjClasses(Entry transformedEntry) throws LdapException {
		transformedEntry.add("objectClass", "inetOrgPerson", "organizationalPerson", "person", "top");
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
	 * @param user
	 * @return
	 * @throws LdapInvalidDnException
	 * @throws LdapException
	 */
	public User loadUser(Entry entry) throws LdapInvalidDnException, LdapException {
		User user = new User();
		user.setDistinguishedName(entry.getDn().getName());
		user.setFirstName(entry.get("cn").getString());
		user.setLastName(entry.get("sn").getString());
		user.setEmail(entry.get("mail").getString());
		user.setTempPassword(entry.get("tempPwd").getString());
		return user;
	}

	/**
	 * @param user
	 * @param postMappedDn
	 * @param mappings
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
	 * @param entry
	 * @return
	 * @throws LdapInvalidAttributeValueException
	 */
	public ModifyRequest generateModifyRequest(Entry entry) throws LdapInvalidAttributeValueException {
		ModifyRequest modifyRequest = new ModifyRequestImpl();
		modifyRequest.setName(entry.getDn());
		Iterator<Attribute> attrs = entry.getAttributes().iterator();
		while (attrs.hasNext()) {
			Attribute attr = attrs.next();
			Modification mod = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, attr.getId(),
					attr.getString());
			modifyRequest.addModification(mod);
		}
		return modifyRequest;
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
