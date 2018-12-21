package com.pers.smartproxy.tools;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author sathyh2
 * 
 *         Tool to backup ApacheDS partition Apache DS does not have a robust
 *         backup tool at this point that works well with version M23. This code
 *         will be used to backup the partition until a production ready tool is
 *         available.
 *
 */
public class BackupPartitionMain {
	final static Logger logger = LoggerFactory.getLogger(BackupPartitionMain.class);
	private static final String ARCHIVE = "rolodex.tar";

	public static void main(String[] args) {
		if (args[0].length() < 1 && args[1].length() < 1) {
			System.out.println("Usage: <partition dir>  <archive loc>");
		} else {
			final File[] files = new File(args[0]).listFiles();
			final File output = new File(args[1], ARCHIVE);
			TarArchiveOutputStream outputStream = null;
			FileOutputStream fileOutputStream = null;
			try {
				fileOutputStream = new FileOutputStream(output);
				outputStream = new TarArchiveOutputStream(fileOutputStream);

				for (File file : files) {
					byte[] bytes = new byte[(int) file.length()];
					TarArchiveEntry entry = new TarArchiveEntry(file.getName());
					entry.setSize(bytes.length);
					outputStream.putArchiveEntry(entry);
					outputStream.write(bytes);
					outputStream.closeArchiveEntry();
				}
			outputStream.close();
			} catch(Exception e){
				logger.info(e.getMessage());
			} finally {
				if (fileOutputStream!=null) {
					try {
						fileOutputStream.close();
					} catch (IOException e) {
						logger.info(e.getMessage());
					}
				}
			}
		}

	}

}


