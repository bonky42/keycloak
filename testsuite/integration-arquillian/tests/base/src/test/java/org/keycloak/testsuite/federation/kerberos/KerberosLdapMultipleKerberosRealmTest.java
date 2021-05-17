/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.federation.kerberos;

import com.sun.tools.javac.util.List;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.storage.ldap.kerberos.LDAPProviderKerberosConfig;
import org.keycloak.testsuite.KerberosEmbeddedServer;
import org.keycloak.testsuite.util.KerberosRule;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KerberosLdapMultipleKerberosRealmTest extends AbstractKerberosMultipleLdapTest {
    private static final String PROVIDER_CONFIG_KEYCLOAK_GROUPA_LOCATION = "classpath:kerberos/multi-ldap/kerberos-groupA-ldap-connection.properties";
    private static final String PROVIDER_CONFIG_KEYCLOAK_GROUPB_LOCATION = "classpath:kerberos/multi-ldap/kerberos-groupB-ldap-connection.properties";
    private static final String PROVIDER_CONFIG_KC2_LOCATION = "classpath:kerberos/multi-ldap/kerberos-kc2-ldap-connection.properties";

    @ClassRule
    public static KerberosRule kerberosRuleKeycloakGroupA = new KerberosRule(PROVIDER_CONFIG_KEYCLOAK_GROUPA_LOCATION, KerberosEmbeddedServer.DEFAULT_KERBEROS_REALM);

    @ClassRule
    public static KerberosRule kerberosRuleKC2 = new KerberosRule(PROVIDER_CONFIG_KC2_LOCATION, KerberosEmbeddedServer.DEFAULT_KERBEROS_REALM_2);

    @ClassRule
    public static KerberosRule kerberosRuleKeycloakGroupB = new KerberosRule(PROVIDER_CONFIG_KEYCLOAK_GROUPB_LOCATION, KerberosEmbeddedServer.DEFAULT_KERBEROS_REALM);


    private static final List<KerberosRule> PROVIDERS_CONFIGURATION = List.of(kerberosRuleKeycloakGroupA, kerberosRuleKC2, kerberosRuleKeycloakGroupB);

    @Override
    protected List getUserStoragesConfig() {
        return PROVIDERS_CONFIGURATION;
    }

    @Override
    protected KerberosRule getKerberosRule() {
        return kerberosRuleKeycloakGroupA;
    }

    private KerberosRule currentRule;

    @Override
    protected CommonKerberosConfig getKerberosConfig() {
        return new LDAPProviderKerberosConfig(getUserStorageConfiguration(currentRule));
    }

    @Test
    public void test01SpnegoLoginUser1A() throws Exception {
        currentRule = kerberosRuleKeycloakGroupA;
        assertSuccessfulSpnegoLogin("user1A@KEYCLOAK.ORG", "user1A", "secret");
        assertUser("user1A", "user1A@keycloak.org", null, null, false);
    }
}
