package com.pers.smartproxy.handlers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

import com.pers.smartproxy.handlers.MappingConditionHandler;

public class MappingConditionHandlerTest {

	private static final String ExternalDn = "o=virtustream";
	private static final String validInputDn = "o=virtustream";

	@InjectMocks
	MappingConditionHandler mappingConditionHandler;

	@Before
	public void init() throws LdapException {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testSearchAttrsMapping() throws LdapException {
		// prepare data
		Entry node = new DefaultEntry();
		node.setDn(new Dn(validInputDn));
		Attribute attribute = new DefaultAttribute(" attrMap ", "oid=uid,cn=sn");
		node.add(attribute);
		mappingConditionHandler.addNodes(node);
		// make the call
		String[] returningAttributesString = { "oid", "cn" };
		String[] returnedAttrs = mappingConditionHandler.applySearchConditionOnAttributes(new Dn(ExternalDn),
				returningAttributesString);
		// assertNotNull(returnedAttrs);
		// assert output
		assertEquals(returnedAttrs[0], "uid");
		assertEquals(returnedAttrs[1], "sn");
	}

	@Test
	public void testUpdatedMods() throws LdapException {
		// prepare data
		Entry node = new DefaultEntry();
		node.setDn(new Dn(validInputDn));
		Attribute parentDn = new DefaultAttribute("parentDn ", "o=virtustream");
		node.add(parentDn);
		Attribute attribute = new DefaultAttribute(" attrMap ", "oid=uid,description=description,cn=sn");
		node.add(attribute);
		Collection<Modification> mods = new ArrayList<Modification>();
		Modification mod = new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "description", "test data");
		mods.add(mod);
		mappingConditionHandler.addNodes(node);
		// make the call
		List<Modification> updatedMods = mappingConditionHandler.getUpdatedMods(new Dn(ExternalDn), mods);
		assertNotNull(updatedMods);
		// assert output
		for (Modification updatedMod : updatedMods) {
			assertNotNull(updatedMod.getAttribute().getId());
			assertNotNull(updatedMod.getAttribute().getString());
		}
	}

	@Test
	public void testApplyConditionWithEntry() throws LdapException {
		// prepare data
		Entry node = new DefaultEntry();
		node.setDn(new Dn("o=inputDn"));
		Attribute parentdnAttr = new DefaultAttribute("parentDn");
		parentdnAttr.add("o=virtustream");
		node.add(parentdnAttr);
		Attribute attr = new DefaultAttribute("endpoint");
		attr.add("o=virtustream");
		node.add(attr);
		Attribute attribute = new DefaultAttribute(" attrMap ", "oid=uid,cn=sn");
		node.add(attribute);
		mappingConditionHandler.addNodes(node);

		List<Entry> entries = mappingConditionHandler.applyCondition(node);
		assertNotNull(entries);
	}

	@Test
	public void testApplyConditionWithDn() throws LdapException {
		// prepare data
		Entry node = new DefaultEntry();
		node.setDn(new Dn(validInputDn));
		Attribute parentdnAttr = new DefaultAttribute("parentDn");
		parentdnAttr.add("o=virtustream");
		node.add(parentdnAttr);
		Attribute attr = new DefaultAttribute("endpoint");
		attr.add("o=virtustream");
		node.add(attr);
		Attribute attribute = new DefaultAttribute(" attrMap ", "oid=uid,cn=sn");
		node.add(attribute);
		mappingConditionHandler.addNodes(node);
		List<Dn> dns = mappingConditionHandler.applyCondition(new Dn(validInputDn));
		assertNotNull(dns);
	}

	@Test
	public void testGetMappedAttrs() throws LdapException {
		String[] sourceAttrs = { "cn", "sn" };
		Entry node = new DefaultEntry();
		node.setDn(new Dn(validInputDn));
		Attribute attribute = new DefaultAttribute(" attrMap ", "oid=uid,cn=sn");
		node.add(attribute);
		mappingConditionHandler.addNodes(node);

		String[] mappedAttrs = mappingConditionHandler.getMappedAttrs(new Dn(validInputDn), sourceAttrs);
		assertNotNull(mappedAttrs);
	}
	
	@Test
	public void testMappingIdMatch() {
		String source = "oid";
		String target = "oid=uid,cn=sn,desc=description,uid=accountName";
		String result = mappingConditionHandler.getMappingId(target, source);
		assertNotNull(result);
		assertEquals(result,"uid");
	}
	
	@Test
	public void testMappingIdNoMatch() {
		String source = "accountName";
		String target = "oid=uid,cn=sn,desc=description,uid=accountName";
		String result = mappingConditionHandler.getMappingId(target, source);
		assertNotNull(result);
		assertEquals(result,"accountName");
	}
	
	@Test
	public void testCompareDns() {
		String sourceDn = "ou=tenant3,ou=tenants,o=emc";
		String targetDn = "ou=users,ou=tenant3,ou=tenants,o=emc";
		String finalDn = "cn=testadd,ou=system";
		
		if (targetDn.trim().contains(sourceDn)){
		 System.out.println("match");
		 if (targetDn.length()>sourceDn.length()){
			 System.out.println(" info: " + sourceDn.compareTo(targetDn));
				String cat = targetDn.substring(0, targetDn.indexOf(sourceDn));
			 System.out.println(cat.concat(finalDn));
		 }
		} else 
			System.out.println(" no match");
	}
}
