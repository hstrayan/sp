package com.pers.smartproxy.tools;

import java.io.File;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class BackupPartitionMainTest {
	   @Mock
	   BackupPartitionMain backup;
	
	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}
	
	@Test
	public void testMethods() throws Exception {
		ClassLoader classLoader = getClass().getClassLoader();
		File file = new File(classLoader.getResource("").getFile());
		File file2 = new File(classLoader.getResource(".").getFile());
		String[] vals = {file.getAbsolutePath(), file2.getAbsolutePath()};
		backup.main(vals);
	}
	
	@Test
	public void testBackupWithInvalidInput() throws Exception {
		String[] vals = {"", ""};
		backup.main(vals);
	}
}
