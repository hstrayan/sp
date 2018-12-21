package com.pers.smartproxy.representations;

/**
 * @author sathyh2
 * 
 * RolodexVault is Hashicorp Vault Value Object
 *
 */
public class RolodexVault {

	/**
	 *  location of hashicorp vault
	 */
	private String url;

	/**
	 * token used
	 */
	private String token;

	/**
	 * context path
	 */
	private String contextPath;

	/**
	 * @return String
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * @param url
	 */
	public void setUrl(String url) {
		this.url = url;
	}

	/**
	 * @return String
	 */
	public String getToken() {
		return token;
	}

	/**
	 * @param token
	 */
	public void setToken(String token) {
		this.token = token;
	}

	/**
	 * @return String
	 */
	public String getContextPath() {
		return contextPath;
	}

	/**
	 * @param contextPath
	 */
	public void setContextPath(String contextPath) {
		this.contextPath = contextPath;
	}

}
