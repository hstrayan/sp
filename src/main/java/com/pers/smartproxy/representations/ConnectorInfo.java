package com.pers.smartproxy.representations;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by pricer3 on 9/7/2017.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ConnectorInfo {
    private String hostname, username, password, sourceUsersDn, sourceTenantDn, ldapType, attributeMap;
    private int port;
    private boolean readOnly;
    private String keyStorePath;
	private String keyStorePwd;
	private boolean useTLS;
	private String encryptedSourcePwd;
	private String isDefault;

    public ConnectorInfo() {

    }

    public ConnectorInfo(String connectionString) {
        String[] ctrParams = connectionString.split(":");
        hostname = ctrParams[0];
        port = Integer.parseInt(ctrParams[1]);
        username = ctrParams[2];
        password = ctrParams[3];
    }

    @JsonProperty
    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    @JsonProperty
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @JsonProperty
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @JsonProperty
    public String getSourceUsersDn() {
        return sourceUsersDn;
    }

    public void setSourceUsersDn(String sourceUsersDn) {
        this.sourceUsersDn = sourceUsersDn;
    }

    @JsonProperty
    public String getSourceTenantDn() {
        return sourceTenantDn;
    }

    public void setSourceTenantDn(String sourceTenantDn) {
        this.sourceTenantDn = sourceTenantDn;
    }

    @JsonProperty
    public String getLdapType() {
        return ldapType;
    }

    public void setLdapType(String ldapType) {
        this.ldapType = ldapType;
    }

    @JsonProperty
    public String getAttributeMap() {
        return attributeMap;
    }

    public void setAttributeMap(String attributeMap) {
        this.attributeMap = attributeMap;
    }

    @JsonProperty
    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    @JsonProperty
    public boolean isReadOnly() {
        return readOnly;
    }

    public void setReadOnly(boolean readOnly) {
        this.readOnly = readOnly;
    }

    @Override
    public String toString() {
        return String.format("%s:%d:%s:%s:", hostname, port, username, password);
    }

    public String getEncryptedSourcePwd() {
		return encryptedSourcePwd;
	}

	public void setEncryptedSourcePwd(String encryptedSourcePwd) {
		this.encryptedSourcePwd = encryptedSourcePwd;
	}
	
	public String getKeyStorePath() {
		return keyStorePath;
	}

	public void setKeyStorePath(String keyStorePath) {
		this.keyStorePath = keyStorePath;
	}

	public String getKeyStorePwd() {
		return keyStorePwd;
	}

	public void setKeyStorePwd(String keyStorePwd) {
		this.keyStorePwd = keyStorePwd;
	}

	public boolean isUseTLS() {
		return useTLS;
	}

	public void setUseTLS(boolean useTLS) {
		this.useTLS = useTLS;
	}

	public void setIsDefault(String isDefault) {
		this.isDefault = isDefault;
		
	}
	
	public String getDefault(){
		return isDefault;
		
	}
}
