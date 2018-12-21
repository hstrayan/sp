package com.pers.smartproxy.utils;
//package com.virtustream.coreservices.rolodex.utils;
//
//import org.apache.directory.api.ldap.model.entry.DefaultEntry;
//import org.apache.directory.api.ldap.model.entry.DefaultModification;
//import org.apache.directory.api.ldap.model.entry.Modification;
//import org.apache.directory.api.ldap.model.entry.ModificationOperation;
//import org.apache.directory.api.ldap.model.exception.LdapException;
//import org.apache.directory.api.ldap.model.message.ModifyRequest;
//import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
//import org.apache.directory.api.ldap.model.name.Dn;
//
///**
// * @author sathyh2
// * 
// *         Testharness to measure Tenancy CRUD operation response times and
// *         throughput
// *
// */
//public class TestHarnessTenantCruds {
//
//	public static void main(String[] args) throws LdapException {
//		if (args.length == 0) {
//			System.out.println(" invalid input args: use ADD or MODIFY or SEARCH or DELETE  <no of iterations>");
//			System.exit(0);
//		}
//		TestTenantCrudsMain testTenantCrudsMain = new TestTenantCrudsMain();
//		String preDn = "ou=tenant";
//		String postDn = ",ou=tenants,o=emc";
//		if (args[0].equalsIgnoreCase("ADD")) {
//			long begin = System.currentTimeMillis();
//			for (int i = 0; i <= new Integer(args[1]).intValue(); i++) {
//				testTenantCrudsMain.testAddEntry(new DefaultEntry(preDn + i + postDn, "objectClass: inetOrgPerson",
//						"objectClass: tenancy", "objectClass: top", "cn: test", "sn: test", "tenantid: testTenantId"));
//			}
//			long end = System.currentTimeMillis();
//			System.out.println("Round trip response time = " + (end - begin) + " millis");
//		}
//		if (args[0].equalsIgnoreCase("DELETE")) {
//			long begin = System.currentTimeMillis();
//			for (int i = 0; i <= new Integer(args[1]).intValue(); i++) {
//				testTenantCrudsMain.testDeleteEntry(preDn + i + postDn);
//			}
//			long end = System.currentTimeMillis();
//			System.out.println("Round trip response time = " + (end - begin) + " millis");
//		}
//		if (args[0].equalsIgnoreCase("MODIFY")) {
//			long begin = System.currentTimeMillis();
//			ModifyRequest modifyRequest = new ModifyRequestImpl();
//			Modification mod1 = new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "street",
//					"123 test street");
//			Modification mod2 = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "description",
//					"test description");
//			modifyRequest.addModification(mod1);
//			modifyRequest.addModification(mod2);
//			for (int i = 0; i <= new Integer(args[1]).intValue(); i++) {
//				modifyRequest.setName(new Dn(preDn + i + postDn));
//				testTenantCrudsMain.testModifyEntry(modifyRequest);
//			}
//			long end = System.currentTimeMillis();
//			System.out.println("Round trip response time = " + (end - begin) + " millis");
//		}
////		if (args[0].equalsIgnoreCase("SEARCH")) {
////			long begin = System.currentTimeMillis();
////			for (int i = 0; i <= new Integer(args[1]).intValue(); i++) {
////				testTenantCrudsMain.testSearchEntry(preDn + i + postDn);
////			}
////			long end = System.currentTimeMillis();
////			System.out.println("Round trip response time = " + (end - begin) + " millis");
////		}
//
//	}
//
//	/**
//	 * no threads, all blocking req-response, calculate throughput
//	 * 
//	 * @param elapsedTime
//	 * @param iterations
//	 * @return
//	 */
//	private static int calculateThroughput(final long elapsedTime, final int iterations, final int loops) {
//		return (iterations *loops) / (int) elapsedTime;
//	}
//
//}
