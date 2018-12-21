package com.pers.smartproxy.representations;

import java.util.EnumSet;

/**
 * Created by pricer3 on 9/7/2017.
 */
public class Enums {
    public enum CustomAttributes
    {
        SOURCETENANTDN("sourceTenantDn"), SOURCEUSERSDN("sourceUsersDn"), CONNECTIONSTRING("connectionString"),
        READONLY("readOnly"), LDAPTYPE("ldapType"), ATTRIBUTEMAP("attrsMap"), TENANTID("tenantId"), HASSOURCE("hasSource"),
        RESOURCESETID("resourceSetId");

        private final String customAttributeName;

        CustomAttributes(String value) {
            customAttributeName = value;
        }

        public String toString() {
            return customAttributeName;
        }

        public static CustomAttributes getByString(String strName) {
            for (final CustomAttributes element : EnumSet.allOf(CustomAttributes.class)) {
                if (element.customAttributeName.equals(strName)) {
                    return element;
                }
            }

            throw new IllegalArgumentException("Can't find " + strName);
        }
    }

    public enum LdapAttributes
    {
        UID("uid"), CN("cn"), SN("sn"), MAIL("mail"),
        TEMPPWD("tempPwd"), USERPASSWORD("userPassword"), OBJECTCLASS("objectClass"),
        OU("ou"), UNICODEPWD("unicodePwd"), USERPRINCIPALNAME("userPrincipalName");

        private final String ldapAttributeName;

        LdapAttributes(String value) {
            ldapAttributeName = value;
        }

        public String toString() {
            return ldapAttributeName;
        }

        public static LdapAttributes getByString(String strName) {
            for (final LdapAttributes element : EnumSet.allOf(LdapAttributes.class)) {
                if (element.ldapAttributeName.equals(strName)) {
                    return element;
                }
            }

            throw new IllegalArgumentException("Can't find " + strName);
        }
    }
}
