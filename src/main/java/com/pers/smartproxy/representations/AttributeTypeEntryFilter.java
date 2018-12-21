package com.pers.smartproxy.representations;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.*;
import org.apache.directory.server.core.api.AttributeTypeProvider;
import org.apache.directory.server.core.api.filtering.EntryFilter;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;

/**
 * Created by pricer3 on 9/5/2017.
 */
public class AttributeTypeEntryFilter implements EntryFilter {

    public static void SetAttributeTypes(Entry entry) {
        entry.getAttributes().forEach(attribute -> {
            try {
                if (attribute.getAttributeType() == null)
                    switch (attribute.getId().toLowerCase()) {
                        case "hassubordinates":
                            MutableAttributeType type = new MutableAttributeType("2.5.18.9");
                            LdapSyntax syntax = new LdapSyntax("1.3.6.1.4.1.1466.115.121.1.7");
                            syntax.setSyntaxChecker(new BooleanSyntaxChecker());
                            type.setSyntax(syntax);
                            type.setEqualityOid("2.5.13.13");
                            type.setNames("hasSubordinates");
                            attribute.apply(type);
                            break;
                        case "objectclass":
                        	type = new MutableAttributeType("2.5.4.0");
                            syntax = new LdapSyntax("1.3.6.1.4.1.1466.115.121.1.38");
                            syntax.setSyntaxChecker(new OidSyntaxChecker());
                            type.setSyntax(syntax);
                            type.setEqualityOid("2.5.13.0");
                            type.setNames("objectClass");
                            attribute.apply(type);
                            break;
                        case "uid":
                            type = new MutableAttributeType("0.9.2342.19200300.100.1.1");
                            syntax = new LdapSyntax("1.3.6.1.4.1.1466.115.121.1.15");
                            syntax.setSyntaxChecker(new DirectoryStringSyntaxChecker());
                            type.setSyntax(syntax);
                            type.setEqualityOid("2.5.13.2");
                            type.setSubstringOid("2.5.13.4");
                            type.setNames("uid", "userid");
                            attribute.apply(type);
                            break;
                        case "cn":
                            type = new MutableAttributeType("2.5.4.3");
                            syntax = new LdapSyntax("1.3.6.1.4.1.1466.115.121.1.15");
                            syntax.setSyntaxChecker(new DirectoryStringSyntaxChecker());
                            type.setSyntax(syntax);
                            type.setEqualityOid("2.5.13.2");
                            type.setNames("cn", "commonName");
                            attribute.apply(type);
                            break;
                        case "sn":
                            type = new MutableAttributeType("2.5.4.4");
                            syntax = new LdapSyntax("1.3.6.1.4.1.1466.115.121.1.15");
                            syntax.setSyntaxChecker(new DirectoryStringSyntaxChecker());
                            type.setSyntax(syntax);
                            type.setEqualityOid("2.5.13.2");
                            type.setNames("sn", "surname");
                            attribute.apply(type);
                            break;
                        case "mail":
                            type = new MutableAttributeType("0.9.2342.19200300.100.1.3");
                            syntax = new LdapSyntax("1.3.6.1.4.1.1466.115.121.1.26");
                            syntax.setSyntaxChecker(new Ia5StringSyntaxChecker());
                            type.setEqualityOid("1.3.6.1.4.1.1466.109.114.2");
                            type.setSubstringOid("1.3.6.1.4.1.1466.109.114.3");
                            type.setSyntax(syntax);
                            type.setNames("mail", "rfc822Mailbox");
                            attribute.apply(type);
                            break;
                        case "userpassword":
                            type = new MutableAttributeType("2.5.4.35");
                            syntax = new LdapSyntax("1.3.6.1.4.1.1466.115.121.1.40");
                            syntax.setSyntaxChecker(new OctetStringSyntaxChecker());
                            type.setSyntax(syntax);
                            type.setEqualityOid("2.5.13.17");
                            type.setNames("userPassword");
                            attribute.apply(type);
                            break;
                        case "ou":
                            type = new MutableAttributeType("2.5.4.11");
                            syntax = new LdapSyntax("1.3.6.1.4.1.1466.115.121.1.15");
                            syntax.setSyntaxChecker(new DirectoryStringSyntaxChecker());
                            type.setSyntax(syntax);
                            type.setEqualityOid("2.5.13.2");
                            type.setNames("ou", "organizationalUnitName");
                            attribute.apply(type);
                            break;
                        case "entryuuid":
                            type = new MutableAttributeType("1.3.6.1.1.16.4");
                            syntax = new LdapSyntax("1.3.6.1.1.16.1");
                            syntax.setSyntaxChecker(new UuidSyntaxChecker());
                            type.setSyntax(syntax);
                            type.setEqualityOid("1.3.6.1.1.16.2");
                            type.setOrderingOid("1.3.6.1.1.16.3");
                            type.setNames("entryUUID");
                            attribute.apply(type);
                            break;
                    }

            } catch (LdapInvalidAttributeValueException ex) {
                System.out.println(ex);
            }
        });
    }

    @Override
    public boolean accept(SearchOperationContext searchOperationContext, Entry entry) throws LdapException {
        SetAttributeTypes(entry);
        return true;
    }

    @Override
    public String toString(String s) {
        return null;
    }
}
