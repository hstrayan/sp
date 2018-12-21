package com.pers.smartproxy.utils;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * @author sathyh2
 * 
 *         Util class for all LDAP CRUD related operations
 *
 */
public final class LdapCrudUtils {

	private static final String TENANTOU = ",ou=tenants,o=emc";
	private static final String TENANTBASE = "o=emc";
	private static final String TENANT = "ou=tenants";

	/**
	 * private constructor
	 */
	private LdapCrudUtils() {
	}

	/**
	 * @param distinguishedName
	 * @param sourceUserNode
	 * @param mappings
	 * @return
	 */
	public static String getUserNameFromDn(String distinguishedName) {
		String dn = getFirstPartDn(distinguishedName);
		String[] userName = dn.split("=");
		return userName[1];
	}

	/**
	 * @param distinguishedName
	 * @return
	 */
	public static String getTenantNameFromDn(String distinguishedName) {
		String[] dn = distinguishedName.split(",");
		String[] tenantName = dn[dn.length - 3].split("=");
		return tenantName[1];
	}

	/**
	 * @param distinguishedName
	 * @return
	 */
	public static String getTenantDnFromUserDn(String distinguishedName) {
		String[] dnsplit = distinguishedName.split(",");
		return dnsplit[dnsplit.length - 3] + "," + dnsplit[dnsplit.length - 2] + "," + dnsplit[dnsplit.length - 1];
	}
	
	/**
	 * @param distinguishedName
	 * @return
	 */
	public static String getTenantDnFromUserDnFirstPart(String distinguishedName) {
		String[] dnsplit = distinguishedName.split(",");
		return dnsplit[dnsplit.length - 3];
	}

	/**
	 * @param strPassword
	 * @return
	 */
	public static String generateSSHA(String strPassword) {
		byte[] password = strPassword.getBytes();
		SecureRandom secureRandom = new SecureRandom();
		byte[] salt = new byte[4];
		secureRandom.nextBytes(salt);
		try {
			MessageDigest crypt = MessageDigest.getInstance("SHA-1");
			crypt.reset();
			crypt.update(password);
			crypt.update(salt);
			byte[] hash = crypt.digest();

			byte[] hashPlusSalt = new byte[hash.length + salt.length];
			System.arraycopy(hash, 0, hashPlusSalt, 0, hash.length);
			System.arraycopy(salt, 0, hashPlusSalt, hash.length, salt.length);

			return new StringBuilder().append("{SSHA}").append(Base64.getEncoder().encodeToString(hashPlusSalt))
					.toString();
		} catch (Exception ex) {
			return new StringBuilder().append(Base64.getEncoder().encodeToString(password)).toString();
		}
	}

	public static String createDnForTranslation(String userName, String sourceUserNode, String mappings) {
		String attr = null;
		if (mappings.contains(",")) {
			List<String> mapList = new ArrayList<String>(Arrays.asList(mappings.split(",")));
			for (String map : mapList) {
				if (isUidPresent(map)) {
					attr = getAttr(map);
				}
			}
		} else {
			if (isUidPresent(mappings)) {
				attr = getAttr(mappings);
			}
		}

		if (attr == null || attr.equalsIgnoreCase("null"))
			return "uid".concat("=").concat(userName).concat(",").concat(sourceUserNode);
		else
			return getFullyQualifiedDn(userName, attr, sourceUserNode);

	}

	/**
	 * @param distinguishedName
	 * @return
	 */
	public static String getFirstPartDn(String distinguishedName) {
		String[] dn = distinguishedName.split(",");
		return dn[0];
	}
	
	/**
	 * @param filter
	 * @return
	 */
	public static String truncFilter(String filter){
	
		if (filter.contains("tenancy")){
			String trunc = filter.replace("tenancy", "inetOrgPerson");
			return trunc;
		} 
		return filter;
	}

	/**
	 * @param dn
	 * @return
	 */
	public static String getTenantFromDn(String dn) {
		String tenantName = null;
		if (dn.contains(",")) {
			String[] dnSplit = dn.split(",");
			int length = dnSplit.length;
			tenantName = dnSplit[length - 3] + "," + dnSplit[length - 2] + "," + dnSplit[length - 1];
		} else {
			tenantName = "ou=".concat(dn).concat(TENANTOU);
		}
		return tenantName;
	}

	/**
	 * @param mapping
	 * @return
	 */
	public static List<String> getSourceTargetAttrs(String mapping, boolean isSource) {
		List<String> sourceAttrs = new ArrayList<String>();
		if (mapping.contains(",")) {
			String[] split = mapping.split(",");
			for (String splitStr : split) {
				addToList(sourceAttrs, splitStr, isSource);
			}
		} else {
			addToList(sourceAttrs, mapping, isSource);
		}
		return sourceAttrs;
	}

	/**
	 * @param list
	 * @param splitStr
	 */
	private static void addToList(List<String> list, String splitStr, boolean isSource) {
		String[] attr = splitStr.split("=");
		if (isSource)
			list.add(attr[0]);
		else
			list.add(attr[1]);
	}

	/**
	 * @param mappings
	 * @return
	 */
	private static String getAttr(String mappings) {
		String[] attrArray = mappings.split("=");
		return attrArray[1];
	}

	/**
	 * @param value
	 * @return
	 */
	private static boolean isUidPresent(String value) {
		if (value.contains("uid") || value.contains("UID")) {
			return true;
		}
		return false;
	}

	/**
	 * @param userName
	 * @param attr
	 * @param sourceUserNode
	 * @return
	 */
	private static String getFullyQualifiedDn(String userName, String attr, String sourceUserNode) {
		return attr.concat("=").concat(userName).concat(",").concat(sourceUserNode);
	}

	public static String createSourceUsersDn(String tenantName, String sourceTenantBase) {
		return String.format("ou=users,ou=%s,%s", tenantName, sourceTenantBase);
	}
	
	public static String getRolodexDn(String dn){
		
		String[] newDn = dn.split(",");
		String rolodexDn = newDn[0]+","+newDn[1]+","+newDn[2]+TENANTOU;
	   return rolodexDn;
	}
	
	public static boolean isValidTenantStruct(String dn){
		String[] splitDn = dn.split(",");
		if (splitDn.length==3) {
			if (splitDn[1].equalsIgnoreCase(TENANT) && splitDn[2].equalsIgnoreCase(TENANTBASE)){
				return true;
			}
		}
		
		return false;
	}

}
