package com.pers.smartproxy.tools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author sathyh2
 * 
 *         Tool to Restore ApacheDS partition
 *
 */
public class RestorePartitionMain {
	final static Logger logger = LoggerFactory.getLogger(RestorePartitionMain.class);
	FileInputStream fileInputStream;
	public static void main(String[] args) throws Exception {
		
		if (args[0].length() < 1 && args[1].length() < 1) {
			System.out.println("Usage: <tar file>  <unzip loc>");
		} else {
			InputStream inputStream = new FileInputStream(args[0]);
			TarArchiveInputStream tarInputStream = new TarArchiveInputStream(inputStream);
			TarArchiveEntry entry;
			while ((entry = tarInputStream.getNextTarEntry()) != null) {
				File file = new File(args[1], entry.getName());
				OutputStream outStream = new FileOutputStream(file);
				IOUtils.copyLarge(tarInputStream, outStream);
				outStream.close();
			}
			inputStream.close();
			tarInputStream.close();
		}
	}

}
