package com.pers.smartproxy.interceptors;

import java.util.Map;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.BaseInterceptor;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.pers.smartproxy.AppConfig;
import com.pers.smartproxy.connectors.ProxyConnector;

/**
 * @author sathyh2
 * 
 * ProxyInterceptor class is the custom interceptor implemented to be inserted in the chain of apacheds interceptors.
 * ProxyInterceptor extends BaseInterceptor class(part of apacheds API suite).
 *
 */
public class ProxyInterceptor extends BaseInterceptor {

	final Logger logger = LoggerFactory.getLogger(ProxyInterceptor.class);

	/**
	 * proxyconnector class
	 */
	private ProxyConnector proxyConnector = null;
	/**
	 * app config
	 */
	private AppConfig configuration = null;
	/**
	 *  map of connectors
	 */
	private Map<String, ProxyConnector> connectorMap = null;
	
	/**
	 * @throws LdapException
	 */
	public ProxyInterceptor() throws LdapException {
		super();
	}

	/**
	 * @throws LdapException
	 */
	public ProxyInterceptor(final AppConfig configuration) throws LdapException {
		super();
		this.configuration = configuration;
	}

	/**
	 * @param proxyConnector
	 */
	public void setProxyConnector(final ProxyConnector proxyConnector) {
		this.proxyConnector = proxyConnector;
	}

	/**
	 * @return
	 */
	public ProxyConnector getProxyConnector() {
		return proxyConnector;
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
	public EntryFilteringCursor search(final SearchOperationContext searchContext) {
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.directory.server.core.api.interceptor.BaseInterceptor#add(org.
	 * apache.directory.server.core.api.interceptor.context.AddOperationContext)
	 */
	@Override
	public  void add(final AddOperationContext addContext) throws LdapException {
		Map<String, ProxyConnector> map = getConnectorMap();
		for (Map.Entry<String, ProxyConnector> entry : map.entrySet()) {
			ProxyConnector connector = entry.getValue();
			connector.add(addContext, getConfiguration().isTransparentProxy());
			//connector.add(addContext.getEntry(), getConfiguration().isTransparentProxy());
		}
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
	public void delete(final DeleteOperationContext deleteContext) throws LdapException {
		Map<String, ProxyConnector> map = getConnectorMap();
		for (Map.Entry<String, ProxyConnector> entry : map.entrySet()) {
			ProxyConnector connector = entry.getValue();
			connector.delete(deleteContext, getConfiguration().isTransparentProxy());
		}
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
	public void modify(final ModifyOperationContext modifyContext) throws LdapException {
		Map<String, ProxyConnector> map = getConnectorMap();
		for (Map.Entry<String, ProxyConnector> entry : map.entrySet()) {
			ProxyConnector connector = entry.getValue();
		//	connector.modify(modifyContext, getConfiguration().isTransparentProxy());
		}
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
	 * @return Map
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

}
