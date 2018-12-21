package com.pers.smartproxy.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.TrustManagerFactory;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

/**
 * @author sathyh2
 * 
 *         Example Client to test TLS ApacheDS connections using a test client
 *         keystore and password combination. The TLS session is started with
 *         the client so that bind operation is performed as a secured
 *         operation. The test parameters needs to be changed based on the
 *         ApacheDS instance connecting to..
 *
 */
public class TestTlsClientMain {

	private static final String HOSTNAME = "localhost";
	private static final int PORT = 10389;
	private static final String KEYSTORE = "client.ks";
	private static final String KEYSTORE_PWD = "secret";
	private static final String USERNAME = "uid=admin,ou=system";
	private static final String PWD = "secret";

	public static void main(String[] args)
			throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
		LdapConnectionConfig ldapConnectionConfig = new LdapConnectionConfig();
		ldapConnectionConfig.setUseTls(true);
		ldapConnectionConfig.setLdapHost(HOSTNAME);
		ldapConnectionConfig.setLdapPort(PORT);
		FileInputStream fileInputStream = new FileInputStream(KEYSTORE);
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] password = new String(KEYSTORE_PWD).toCharArray();
		keyStore.load(fileInputStream, password);
		fileInputStream.close();
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);
		ldapConnectionConfig.setTrustManagers(trustManagerFactory.getTrustManagers());
		LdapNetworkConnection connection = new LdapNetworkConnection(ldapConnectionConfig);
		try {
			// unsecure
			connection.connect();
			// Start TLS session
			connection.startTls();
			// secure
			connection.bind(USERNAME, PWD);
		} catch (LdapException e) {
			e.printStackTrace();
		}
	}
}
