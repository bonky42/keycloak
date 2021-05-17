/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.DefaultHttpClient;
import org.ietf.jgss.GSSCredential;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticatorFactory;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.events.Details;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.testsuite.AbstractAuthTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.AuthServerTestEnricher;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude.AuthServer;
import org.keycloak.testsuite.auth.page.AuthRealm;
import org.keycloak.testsuite.pages.AccountPasswordPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.util.KerberosRule;
import org.keycloak.testsuite.util.LDAPTestConfiguration;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.TestEventsLogger;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.sasl.Sasl;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.security.Principal;
import java.util.*;
import java.util.function.Consumer;

import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * Contains just helper methods. No test methods.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@AuthServerContainerExclude(AuthServer.REMOTE)
public abstract class AbstractKerberosMultipleLdapTest extends AbstractKerberosTest {


    @Override
    protected ComponentRepresentation getUserStorageConfiguration() {
        return null;
    }


    protected abstract List<KerberosRule> getUserStoragesConfig();

    protected ComponentRepresentation getUserStorageConfiguration(KerberosRule kRule) {
        Map<String,String> kerberosConfig = kRule.getConfig();
        MultivaluedHashMap<String, String> config = toComponentConfig(kerberosConfig);

        UserStorageProviderModel model = new UserStorageProviderModel();
        model.setLastSync(0);
        model.setChangedSyncPeriod(-1);
        model.setFullSyncPeriod(-1);
        model.setName(config.getFirst(LDAPTestConfiguration.NAME));
        model.setPriority(Integer.parseInt(config.getFirst(LDAPTestConfiguration.PRIORITY)));
        model.setProviderId(LDAPStorageProviderFactory.PROVIDER_NAME);
        model.setConfig(config);

        ComponentRepresentation rep = ModelToRepresentation.toRepresentationWithoutConfig(model);
        return rep;
    }

    @Before
    @Override
    public void beforeAbstractKeycloakTest() throws Exception {
        super.beforeAbstractKeycloakTest();
        for (KerberosRule kRule: getUserStoragesConfig()) {
            ComponentRepresentation rep = getUserStorageConfiguration(kRule);
            System.out.println(testRealmResource());
            System.out.println(testRealmResource().components());
            Response resp = testRealmResource().components().add(rep);
            getCleanup().addComponentId(ApiUtil.getCreatedId(resp));
            resp.close();
        }
    }
}
