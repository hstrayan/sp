package com.pers.smartproxy.tools;

import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class RestorePartitionMainTest {
    @Mock
	RestorePartitionMain restore;
	
	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}
	
	@Test
	public void testRestoreWithInput() throws Exception {
	
		ClassLoader classLoader = getClass().getClassLoader();
		File file = new File(classLoader.getResource("xyz.tar").getFile());
		File file2 = new File(classLoader.getResource(".").getFile());
		String[] vals = {file.getAbsolutePath(), file2.getAbsolutePath()};
		RestorePartitionMain.main(vals);
		}
	
	@Test
	public void testRestoreWithInvalidInput() throws Exception {
		ClassLoader classLoader = getClass().getClassLoader();
		File file = new File(classLoader.getResource("xyz.tar").getFile());
		File file2 = new File(classLoader.getResource(".").getFile());
		String[] vals = {"",""};
		RestorePartitionMain.main(vals);
	}
	
	
	
}
