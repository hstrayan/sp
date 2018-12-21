package com.pers.smartproxy.representations;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author sathyh2
 * 
 *         Endpoint representation object
 *
 */
public class EndpointConnection {

	/**
	 * hostname
	 */
	@NotNull
	private String hostName;

	/**
	 * port
	 */
	@NotNull
	private int port;
	/**
	 * IP Address
	 */
	@NotNull
	private String ipAddress;

	/**
	 * username
	 */
	@NotNull
	private String userName;
	/**
	 * password
	 */
	@NotNull
	private String password;

	/**
	 *  get hostname
	 * @return String
	 */
	@JsonProperty
	public String getHostName() {
		return hostName;
	}

	/**
	 * @param hostName
	 */
	@JsonProperty
	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	/**
	 * get port
	 * @return int
	 */
	@JsonProperty
	public int getPort() {
		return port;
	}

	/**
	 * @param port
	 */
	@JsonProperty
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 *  get IP address
	 * @return ipAddress
	 */
	@JsonProperty
	public String getIPAddress() {
		return ipAddress;
	}

	/**
	 * @param ipAddress
	 */
	@JsonProperty
	public void setIPAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	/**
	 * get username
	 * @return String
	 */
	@JsonProperty
	public String getUserName() {
		return userName;
	}

	/**
	 * @param userName
	 */
	@JsonProperty
	public void setUserName(String userName) {
		this.userName = userName;
	}

	/**
	 * get password
	 * @return String
	 */
	@JsonProperty
	public String getPassword() {
		return password;
	}

	/**
	 * @param password
	 */
	@JsonProperty
	public void setPassword(String password) {
		this.password = password;
	}

}
