package com.pers.smartproxy.integ;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.services.DSEngine;

@CreateDS(name = "ConnectionTest", partitions = {
		@CreatePartition(name = "ConnectionTest", suffix = "ou=ConnectionTest,o=emc", contextEntry = @ContextEntry(entryLdif = "dn: ou=ConnectionTest,o=emc\n"
				+ "dc: example\n" + "objectClass: top\n" + "objectClass: organizationalUnit\n\n")) }, enableChangeLog = false)
@CreateLdapServer(transports = {
		@CreateTransport(protocol = "LDAP", address = "localhost", port = 10389) }, allowAnonymousAccess = true)
@ApplyLdifs({ "dn: ou=test,ou=ConnectionTest,o=emc", "objectClass: top", "objectClass: organizationalUnit", "ou: test", "",
	"dn: ou=test,ou=ConnectionTest,o=emc", "objectClass: top", "objectClass: organizationalUnit", "ou: groups",
	"", "dn: uid=imadmin,ou=test,ou=ConnectionTest,o=emc", "objectClass: top", "objectClass: person",
	"uniqueMember: uid=imadmin", "description: user", "cn: imadmin", "" })
public class LdapConnectionTest extends AbstractLdapTestUnit {

	@Mock
	DSEngine engine;
	@Mock
	LdapNetworkConnection remoteConnection;
	LdapNetworkConnection localConnection;
	@Mock
	private DirectoryService directoryService;

	boolean isConnected = false;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}

	private LdapNetworkConnection getConnection() throws LdapException {
		if (localConnection == null) {
			localConnection = new LdapNetworkConnection("localhost", 12389);
			isConnected = true;
		}
		return localConnection;
	}

	private void closeConnection() throws IOException {
		if (localConnection != null) {
			localConnection.close();
			localConnection = null;
			isConnected = false;
		}
	}
	@Test
	public void testIsConnectedLocally() throws LdapException {
		localConnection = getConnection();

		assertTrue(isConnected);
		assertNotNull(localConnection);
	}

	@Test
	public void testIsNotConnectedLocally() throws LdapException, IOException {
		closeConnection();

		assertFalse(isConnected);
		assertNull(localConnection);
	}
}
