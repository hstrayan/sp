package com.pers.smartproxy.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author sathyh2
 * 
 * Code to create CSV data set of auto generated DNs
 *
 */
public class JMeterTestUtilMain {
	final static String DNPART = "cn=testadd";
	final static String RDN = "ou=system";
	final static String COMMA = ",";
	public static void main(String[] args) throws IOException {
		if (args[0] == null && args[1] == null) {
			System.out.println("invalid input: format is <filename> <number of DNs>");
			System.exit(0);
		}
		PrintWriter printWriter = new PrintWriter(new FileWriter(args[0]));
		int lines = new Integer(args[1]).intValue();
		for (int i = 0; i <= lines; i++) {
			StringBuffer sb = new StringBuffer(DNPART);
			sb.append(i).append(COMMA).append(RDN);
			printWriter.write(sb.toString());
			printWriter.write("\r\n");
		}
		printWriter.close();
	}

}
