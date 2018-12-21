package com.pers.smartproxy.representations;

import java.util.List;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author sathyh2
 * 
 * Endpoint representation for servers registered within Rolodex
 *
 */
public class Endpoint {
	
	/**
	 * hostname
	 */
	@NotNull
	private String serverName;
	
	/**
	 * server IP
	 */
	@NotNull
	private String serverIP;
	
	/**
	 * server location
	 */
	
	private String serverLocation;

	/**
	 * server attrs
	 */
	@NotNull
	private List<ProxyConfiguration> proxyAttributes;
	
	
	/**
	 * @return
	 */
	@JsonProperty
	public String getServerName() {
		return serverName;
	}
	/**
	 * @param serverName
	 */
	@JsonProperty
	public void setServerName(String serverName) {
		this.serverName = serverName;
	}
	/**
	 * @return
	 */
	@JsonProperty
	public String getServerIP() {
		return serverIP;
	}
	/**
	 * @param serverIP
	 */
	@JsonProperty
	public void setServerIP(String serverIP) {
		this.serverIP = serverIP;
	}
	

	/**
	 * @return
	 */
	@JsonProperty
	public String getServerLocation() {
		return serverLocation;
	}
	/**
	 * @param serverLocation
	 */
	@JsonProperty
	public void setServerLocation(String serverLocation) {
		this.serverLocation = serverLocation;
	}
	
	/**
	 * @param proxyAttributes
	 */
	@JsonProperty
	public void setProxyAttributes(List<ProxyConfiguration> proxyAttributes) {
		this.proxyAttributes = proxyAttributes;
	}
	
	/**
	 * @return
	 */
	@JsonProperty
	public List<ProxyConfiguration> getProxyAttributes() {
		return proxyAttributes;
	}
	
	
}
