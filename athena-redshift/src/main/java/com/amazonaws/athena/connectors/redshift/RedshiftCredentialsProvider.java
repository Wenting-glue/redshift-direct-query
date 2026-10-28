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

import com.amazonaws.athena.connector.credentials.Credentials;
import com.amazonaws.athena.connector.credentials.CredentialsProvider;
import com.amazonaws.athena.connector.credentials.DefaultCredentialsProvider;
import com.amazonaws.athena.connector.lambda.exceptions.AthenaConnectorException;
import com.amazonaws.athena.connector.lambda.security.KmsEncryptionProvider;
import com.amazonaws.athena.connectors.jdbc.connection.DatabaseConnectionConfig;
import org.apache.commons.lang3.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.services.glue.model.ErrorDetails;
import software.amazon.awssdk.services.glue.model.FederationSourceErrorCode;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

import static com.amazonaws.athena.connector.lambda.connection.EnvironmentConstants.AUTHENTICATION_TYPE;
import static com.amazonaws.athena.connector.lambda.connection.EnvironmentConstants.DB_STS_TOKEN;
import static com.amazonaws.athena.connector.lambda.connection.EnvironmentConstants.FAS_TOKEN;
import static com.amazonaws.athena.connector.lambda.connection.EnvironmentConstants.SERVICE_KMS;

/**
 * Redshift database credentials for the connection's authentication type:
 * <ul>
 *     <li>BASIC (default): user and password from a Secrets Manager secret.</li>
 *     <li>IAM: AWS credentials that the Redshift JDBC driver exchanges for temporary database credentials. Uses the
 *     connection role's credentials if present, otherwise the caller's (FAS) credentials. Requires the
 *     {@code jdbc:redshift:iam://} connection string scheme.</li>
 * </ul>
 */
public class RedshiftCredentialsProvider
        implements CredentialsProvider
{
    private static final String IAM_AUTHENTICATION_TYPE = "IAM";

    // Redshift JDBC driver properties for IAM authentication
    private static final String ACCESS_KEY_ID = "AccessKeyID";
    private static final String SECRET_ACCESS_KEY = "SecretAccessKey";
    private static final String SESSION_TOKEN = "SessionToken";
    private static final String DB_USER = "DbUser";
    private static final String GROUP_FEDERATION = "GroupFederation";

    private final Credentials credentials;

    private RedshiftCredentialsProvider(Credentials credentials)
    {
        this.credentials = credentials;
    }

    /**
     * @param secretFetcher returns the secret value for a secret name (BASIC only)
     * @return the provider, or null for BASIC connections without a secret
     */
    public static RedshiftCredentialsProvider create(Map<String, String> configOptions,
                                                     DatabaseConnectionConfig databaseConnectionConfig,
                                                     AwsRequestOverrideConfiguration requestOverrideConfiguration,
                                                     KmsEncryptionProvider kmsEncryptionProvider,
                                                     Function<String, String> secretFetcher)
    {
        if (IAM_AUTHENTICATION_TYPE.equalsIgnoreCase(getOption(configOptions, AUTHENTICATION_TYPE))) {
            AwsCredentials awsCredentials = getAwsCredentials(configOptions, requestOverrideConfiguration, kmsEncryptionProvider);
            Map<String, String> properties = new HashMap<>(getIdentityProperties(configOptions, databaseConnectionConfig.getJdbcConnectionString()));
            properties.put(ACCESS_KEY_ID, awsCredentials.accessKeyId());
            properties.put(SECRET_ACCESS_KEY, awsCredentials.secretAccessKey());
            if (awsCredentials instanceof AwsSessionCredentials) {
                properties.put(SESSION_TOKEN, ((AwsSessionCredentials) awsCredentials).sessionToken());
            }
            Map<String, String> iamProperties = Map.copyOf(properties);
            return new RedshiftCredentialsProvider(() -> iamProperties);
        }
        String secretName = databaseConnectionConfig.getSecret();
        return StringUtils.isBlank(secretName) ? null
                : new RedshiftCredentialsProvider(new DefaultCredentialsProvider(secretFetcher.apply(secretName)).getCredential());
    }

    @Override
    public Credentials getCredential()
    {
        return credentials;
    }

    /**
     * Connection role credentials if present, otherwise the caller's (FAS) credentials.
     */
    private static AwsCredentials getAwsCredentials(Map<String, String> configOptions,
                                                    AwsRequestOverrideConfiguration requestOverrideConfiguration,
                                                    KmsEncryptionProvider kmsEncryptionProvider)
    {
        String kmsKeyId = getOption(configOptions, SERVICE_KMS);
        String roleToken = getOption(configOptions, DB_STS_TOKEN);
        if (StringUtils.isNotBlank(roleToken)) {
            return kmsEncryptionProvider.getFasCredentials(kmsKeyId, roleToken);
        }
        if (requestOverrideConfiguration != null && requestOverrideConfiguration.credentialsProvider().isPresent()) {
            return requestOverrideConfiguration.credentialsProvider().get().resolveCredentials();
        }
        String fasToken = getOption(configOptions, FAS_TOKEN);
        if (StringUtils.isNotBlank(fasToken)) {
            return kmsEncryptionProvider.getFasCredentials(kmsKeyId, fasToken);
        }
        throw new AthenaConnectorException("No AWS credentials available for Redshift IAM authentication",
                ErrorDetails.builder().errorCode(FederationSourceErrorCode.INVALID_CREDENTIALS_EXCEPTION.toString()).build());
    }

    /**
     * Maps the IAM identity to a database user: DbUser if configured, otherwise GroupFederation. Adds neither if the
     * JDBC URL already sets one.
     */
    private static Map<String, String> getIdentityProperties(Map<String, String> configOptions, String jdbcConnectionString)
    {
        String dbUser = getOption(configOptions, DB_USER);
        if (StringUtils.isNotBlank(dbUser)) {
            return Map.of(DB_USER, dbUser);
        }
        String url = StringUtils.defaultString(jdbcConnectionString).toLowerCase(Locale.ROOT);
        if (url.contains(DB_USER.toLowerCase(Locale.ROOT) + "=") || url.contains(GROUP_FEDERATION.toLowerCase(Locale.ROOT) + "=")) {
            return Map.of();
        }
        return Map.of(GROUP_FEDERATION, "true");
    }

    private static String getOption(Map<String, String> configOptions, String key)
    {
        if (configOptions == null) {
            return null;
        }
        if (configOptions.containsKey(key)) {
            return configOptions.get(key);
        }
        return configOptions.entrySet().stream()
                .filter(entry -> key.equalsIgnoreCase(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }
}
