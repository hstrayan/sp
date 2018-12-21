package com.pers.smartproxy.integ;

import static org.junit.Assert.assertTrue;

import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.util.Network;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.NoVerificationTrustManager;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.annotations.SaslMechanism;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.ldap.handlers.sasl.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.plain.PlainMechanismHandler;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * @author sathyh2 
 * 
 * LDAPSSLConnection Test
 */
// @RunWith(FrameworkRunner.class)
@CreateLdapServer(transports = { @CreateTransport(protocol = "LDAP"),
		@CreateTransport(protocol = "LDAPS") }, saslHost = "localhost", saslMechanisms = {
				@SaslMechanism(name = SupportedSaslMechanisms.PLAIN, implClass = PlainMechanismHandler.class),
				@SaslMechanism(name = SupportedSaslMechanisms.CRAM_MD5, implClass = CramMd5MechanismHandler.class),
				@SaslMechanism(name = SupportedSaslMechanisms.DIGEST_MD5, implClass = DigestMd5MechanismHandler.class)

}, extendedOpHandlers = { StartTlsHandler.class })
public class LdapSSLConnectionTest extends AbstractLdapTestUnit {
	private LdapConnectionConfig sslConfig;

	private LdapConnectionConfig tlsConfig;
	@Mock
	LdapServer ldapServer;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
		sslConfig = new LdapConnectionConfig();
		sslConfig.setLdapHost(Network.LOOPBACK_HOSTNAME);
		sslConfig.setUseSsl(true);
		sslConfig.setLdapPort(ldapServer.getPortSSL());
		sslConfig.setTrustManagers(new NoVerificationTrustManager());
		tlsConfig = new LdapConnectionConfig();
		tlsConfig.setLdapHost(Network.LOOPBACK_HOSTNAME);
		tlsConfig.setLdapPort(ldapServer.getPort());
		tlsConfig.setTrustManagers(new NoVerificationTrustManager());

	}

	@Test
	public void testBindRequestSSLConfig() throws Exception {
		try (LdapNetworkConnection connection = new LdapNetworkConnection(sslConfig)) {
			assertTrue(connection.getConfig().isUseSsl());

		}
	}

}