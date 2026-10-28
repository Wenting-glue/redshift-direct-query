/*-
 * #%L
 * athena-redshift
 * %%
 * Copyright (C) 2019 - 2026 Amazon Web Services
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package com.amazonaws.athena.connectors.redshift;

import com.amazonaws.athena.connector.lambda.exceptions.AthenaConnectorException;
import com.amazonaws.athena.connector.lambda.security.KmsEncryptionProvider;
import com.amazonaws.athena.connectors.jdbc.connection.DatabaseConnectionConfig;
import org.junit.Before;
import org.junit.Test;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RedshiftCredentialsProviderTest
{
    private static final String URL = "jdbc:redshift:iam://host:5439/dev";
    private static final DatabaseConnectionConfig IAM_CONFIG = new DatabaseConnectionConfig("default", "redshift", URL);
    private static final AwsSessionCredentials ROLE = AwsSessionCredentials.create("roleKey", "roleSecret", "roleToken");
    private static final AwsSessionCredentials FAS = AwsSessionCredentials.create("fasKey", "fasSecret", "fasToken");

    private KmsEncryptionProvider kmsEncryptionProvider;
    private Map<String, String> configOptions;

    @Before
    public void setUp()
    {
        kmsEncryptionProvider = mock(KmsEncryptionProvider.class);
        when(kmsEncryptionProvider.getFasCredentials("kms", "role-token")).thenReturn(ROLE);
        when(kmsEncryptionProvider.getFasCredentials("kms", "fas-token")).thenReturn(FAS);
        configOptions = new HashMap<>();
        configOptions.put("authentication_type", "IAM");
        configOptions.put("service_kms_key_id", "kms");
    }

    @Test
    public void basicUsesSecret()
    {
        DatabaseConnectionConfig config = new DatabaseConnectionConfig("default", "redshift", "jdbc:redshift://host:5439/dev", "secret");

        Map<String, String> properties = RedshiftCredentialsProvider.create(Map.of(), config, null, kmsEncryptionProvider,
                secretName -> "{\"username\": \"user\", \"password\": \"pass\"}").getCredentialMap();

        assertEquals(Map.of("user", "user", "password", "pass"), properties);
    }

    @Test
    public void basicWithoutSecretReturnsNull()
    {
        assertNull(RedshiftCredentialsProvider.create(Map.of(), IAM_CONFIG, null, kmsEncryptionProvider, secretName -> "unused"));
    }

    @Test
    public void iamWithRoleUsesRoleCredentials()
    {
        configOptions.put("db_sts_token", "role-token");
        configOptions.put("fas_token", "fas-token");

        Map<String, String> properties = create(overrideWith(FAS));

        assertEquals("roleKey", properties.get("AccessKeyID"));
        assertEquals("roleSecret", properties.get("SecretAccessKey"));
        assertEquals("roleToken", properties.get("SessionToken"));
    }

    @Test
    public void iamWithoutRoleUsesCallerCredentialsFromRequest()
    {
        Map<String, String> properties = create(overrideWith(FAS));

        assertEquals("fasKey", properties.get("AccessKeyID"));
        verify(kmsEncryptionProvider, never()).getFasCredentials(anyString(), anyString());
    }

    @Test
    public void iamWithoutRoleFallsBackToFasToken()
    {
        configOptions.put("fas_token", "fas-token");

        Map<String, String> properties = create(null);

        assertEquals("fasKey", properties.get("AccessKeyID"));
    }

    @Test
    public void iamWithoutCredentialsFails()
    {
        AthenaConnectorException exception = assertThrows(AthenaConnectorException.class, () -> create(null));

        assertTrue(exception.getMessage().contains("No AWS credentials available"));
    }

    @Test
    public void iamDefaultsToGroupFederation()
    {
        Map<String, String> properties = create(overrideWith(FAS));

        assertEquals("true", properties.get("GroupFederation"));
        assertFalse(properties.containsKey("DbUser"));
    }

    @Test
    public void iamUsesConfiguredDbUser()
    {
        configOptions.put("DbUser", "analyst");

        Map<String, String> properties = create(overrideWith(FAS));

        assertEquals("analyst", properties.get("DbUser"));
        assertFalse(properties.containsKey("GroupFederation"));
    }

    @Test
    public void iamKeepsIdentitySetInJdbcUrl()
    {
        DatabaseConnectionConfig config = new DatabaseConnectionConfig("default", "redshift", URL + "?GroupFederation=false");

        Map<String, String> properties = RedshiftCredentialsProvider.create(configOptions, config, overrideWith(FAS),
                kmsEncryptionProvider, secretName -> "unused").getCredentialMap();

        assertFalse(properties.containsKey("GroupFederation"));
        assertFalse(properties.containsKey("DbUser"));
    }

    @Test
    public void authenticationTypeIsCaseInsensitive()
    {
        configOptions.remove("authentication_type");
        configOptions.put("AUTHENTICATION_TYPE", "iam");

        assertEquals("fasKey", create(overrideWith(FAS)).get("AccessKeyID"));
    }

    private Map<String, String> create(AwsRequestOverrideConfiguration overrideConfig)
    {
        return RedshiftCredentialsProvider.create(configOptions, IAM_CONFIG, overrideConfig, kmsEncryptionProvider,
                secretName -> "unused").getCredentialMap();
    }

    private static AwsRequestOverrideConfiguration overrideWith(AwsSessionCredentials credentials)
    {
        return AwsRequestOverrideConfiguration.builder()
                .credentialsProvider(software.amazon.awssdk.auth.credentials.StaticCredentialsProvider.create(credentials))
                .build();
    }
}
