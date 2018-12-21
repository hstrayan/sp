package com.pers.smartproxy.representations;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author sathyh2
 * 
 *         USER Object to deserialize json POST request
 *
 */

/**
 * @author sathyh2
 *
 */
/**
 * @author sathyh2
 *
 */
public class User {

	/**
	 * distinguishedName
	 */
	@NotNull
	private String distinguishedName;

	/**
	 * first name
	 */
	private String firstName;
	/**
	 * last name
	 */
	private String lastName;

	/**
	 * user name
	 */
	private String userName;
	/**
	 * email
	 */
	private String email;
	/**
	 * cell phone
	 */
	private String cellPhone;
	/**
	 * street address
	 */
	private String streetAddress;

	/**
	 * tenantID
	 */
	private String tenantID;
	/**
	 * temp passwd
	 */
	private String tempPassword;
	/**
	 * password - unicode, userpassword types
	 */
	private String password;
	/**
	 * new password - unicode, userpassword types
	 */
	private String newPassword;
	/**
	 * source password type - is it unicode- if not revert to userpassword
	 */
	private boolean isSourcePwdUnicode;
	
	/**
	 * userPrincipal name is equaivalent of uid in Active Directory
	 * 
	 */
	private boolean isUserPrincipalName;
	
	/**
	 * sourceOnly - if  Add operations perfomed also on Source
	 */
	private boolean addSource;
	/**
	 * sourceOnly - if  modify operations perfomed also on Source
	 */
	private boolean modifySource;
	/**
	 * sourceOnly -  if  delete operations perfomed also on Source
	 */
	private boolean deleteSource;
	
	/**
	 * @return String
	 */
	@JsonProperty
	public String getDistinguishedName() {
		return distinguishedName;
	}

	/**
	 * @param distinguishedName
	 */
	@JsonProperty
	public void setDistinguishedName(String distinguishedName) {
		this.distinguishedName = distinguishedName;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getFirstName() {
		return firstName;
	}

	/**
	 * @param firstName
	 */
	@JsonProperty
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getLastName() {
		return lastName;
	}

	/**
	 * @param lastName
	 */
	@JsonProperty
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	/**
	 * @return String
	 */
	public String getUserName() {
		return userName;
	}

	/**
	 * @param userName
	 */
	public void setUserName(String userName) {
		this.userName = userName;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getEmail() {
		return email;
	}

	/**
	 * @param email
	 */
	@JsonProperty
	public void setEmail(String email) {
		this.email = email;
	}

	/**
	 * @return String
	 */
	public String getCellPhone() {
		return cellPhone;
	}

	/**
	 * @param cellPhone
	 */
	public void setCellPhone(String cellPhone) {
		this.cellPhone = cellPhone;
	}

	/**
	 * @return String
	 */
	public String getStreetAddress() {
		return streetAddress;
	}

	/**
	 * @param streetAddress
	 */
	public void setStreetAddress(String streetAddress) {
		this.streetAddress = streetAddress;
	}

	/**
	 * @return String
	 */
	@JsonProperty
	public String getTenantID() {
		return tenantID;
	}

	/**
	 * @param tenantID
	 */
	@JsonProperty
	public void setTenantID(String tenantID) {
		this.tenantID = tenantID;
	}

	/**
	 * @return String
	 */
	public String getTempPassword() {
		return tempPassword;
	}

	/**
	 * @param tempPassword
	 */
	public void setTempPassword(String tempPassword) {
		this.tempPassword = tempPassword;
	}

	/**
	 * @return String
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * @param password
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * @return String
	 */
	public String getNewPassword() {
		return newPassword;
	}
	/**
	 * @param newPassword
	 */
	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}
	/**
	 * @return boolean true/false
	 */
	@JsonProperty
	public boolean isSourcePwdUnicode() {
		return isSourcePwdUnicode;
	}
	/**
	 * @param isSourcePwdUnicode
	 */
	@JsonProperty
	public void setSourcePwdUnicode(boolean isSourcePwdUnicode) {
		this.isSourcePwdUnicode = isSourcePwdUnicode;
	}
	
	/**
	 * @return boolean true/false
	 */
	public boolean isUserPrincipalName() {
		return isUserPrincipalName;
	}

	/**
	 * @param isUserPrincipalName
	 */
	public void setUserPrincipalName(boolean isUserPrincipalName) {
		this.isUserPrincipalName = isUserPrincipalName;
	}
	
	/**
	 * @return true/false
	 */
	public boolean isAddSource() {
		return addSource;
	}
	/**
	 * @param addSource
	 */
	public void setAddSource(boolean addSource) {
		this.addSource = addSource;
	}
	/**
	 * @return true/false
	 */
	public boolean isModifySource() {
		return modifySource;
	}

	/**
	 * @param modifySource
	 */
	public void setModifySource(boolean modifySource) {
		this.modifySource = modifySource;
	}

	/**
	 * @return true/false
	 */
	public boolean isDeleteSource() {
		return deleteSource;
	}

	/**
	 * @param deleteSource
	 */
	public void setDeleteSource(boolean deleteSource) {
		this.deleteSource = deleteSource;
	}
}
