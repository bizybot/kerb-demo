package org.elasticsearch.xpack.client.demo.kerberos.support;

import java.io.IOException;
import java.security.AccessController;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.HashSet;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;

import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.KerberosCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.client.RestClientBuilder.HttpClientConfigCallback;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.settings.SecureString;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

public class CustomHttpClientConfigCallbackHandler implements HttpClientConfigCallback {
    private static final String CRED_CONF_NAME = "ESClientLoginConf";
    private static final Oid SPNEGO_OID = getSpnegoOid();

    private static Oid getSpnegoOid() {
        Oid oid = null;
        try {
            oid = new Oid("1.3.6.1.5.5.2");
        } catch (GSSException gsse) {
            throw ExceptionsHelper.convertToRuntime(gsse);
        }
        return oid;
    }

    private final String userPrincipalName;
    private final SecureString password;

    /**
     * @param userPrincipalName
     * @param password may be {@code null} if one wants to use keytabs
     */
    public CustomHttpClientConfigCallbackHandler(final String userPrincipalName, @Nullable final SecureString password) {
        this.userPrincipalName = userPrincipalName;
        this.password = password;
    }

    @Override
    public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
        final Lookup<AuthSchemeProvider> authSchemeRegistry =
                RegistryBuilder.<AuthSchemeProvider>create().register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory()).build();

        GSSManager gssManager = GSSManager.getInstance();
        GSSCredential credential;
        try {
            LoginContext loginContext = login();
            credential = Subject.doAs(loginContext.getSubject(), new PrivilegedExceptionAction<GSSCredential>() {

                @Override
                public GSSCredential run() throws Exception {
                    return gssManager.createCredential(null, GSSCredential.DEFAULT_LIFETIME, SPNEGO_OID,
                            GSSCredential.INITIATE_ONLY);
                }

            });
            KerberosCredentialsProvider credentialsProvider = new KerberosCredentialsProvider();
            credentialsProvider.setCredentials(
                    new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT, AuthScope.ANY_REALM, AuthSchemes.SPNEGO),
                    new KerberosCredentials(credential));
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        } catch (PrivilegedActionException e) {
            throw new RuntimeException(e);
        }

        httpClientBuilder.setDefaultAuthSchemeRegistry(authSchemeRegistry);

        SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
        try {
            sslContextBuilder.loadTrustMaterial(null, new TrustAllStrategy());
            httpClientBuilder.setSSLContext(sslContextBuilder.build());
            httpClientBuilder.setSSLStrategy(new SSLIOSessionStrategy(sslContextBuilder.build(), new NoopHostnameVerifier()));
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new RuntimeException(e);
        }

        return httpClientBuilder;
    }

    public LoginContext login() throws PrivilegedActionException {
        return AccessController.doPrivileged((PrivilegedExceptionAction<LoginContext>) () -> {
            final Subject subject = new Subject(false, Collections.singleton(new KerberosPrincipal(userPrincipalName)),
                    new HashSet<>(), new HashSet<>());
            final CallbackHandler callback;
            if (password != null) {
                callback = new KrbCallbackHandler(userPrincipalName, password);
            } else {
                callback = null;
            }
            final LoginContext loginContext = new LoginContext(CRED_CONF_NAME, subject, callback, null);
            loginContext.login();
            return loginContext;
        });
    }

    /**
     * This class matches {@link AuthScope} and based on that returns
     * {@link Credentials}. Only supports {@link AuthSchemes#SPNEGO} in
     * {@link AuthScope#getScheme()}
     */
    static class KerberosCredentialsProvider implements CredentialsProvider {
        private AuthScope authScope;
        private Credentials credentials;

        @Override
        public void setCredentials(AuthScope authscope, Credentials credentials) {
        		if( authscope.getScheme().regionMatches(true, 0, AuthSchemes.SPNEGO, 0, AuthSchemes.SPNEGO.length()) == false) {
                throw new IllegalArgumentException("Only " + AuthSchemes.SPNEGO + " auth scheme is supported in AuthScope");
            }
            this.authScope = authscope;
            this.credentials = credentials;
        }

        @Override
        public Credentials getCredentials(AuthScope authscope) {
            assert this.authScope != null && authscope != null;
            return authscope.match(this.authScope) > -1 ? this.credentials : null;
        }

        @Override
        public void clear() {
            this.authScope = null;
            this.credentials = null;
        }
    }

    /**
     * Jaas call back handler to provide credentials.
     */
    static class KrbCallbackHandler implements CallbackHandler {
        private final String principal;
        private final SecureString password;

        KrbCallbackHandler(final String principal, final SecureString password) {
            this.principal = principal;
            this.password = password;
        }

        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    if (pc.getPrompt().contains(principal)) {
                        pc.setPassword(password.getChars());
                        break;
                    }
                }
            }
        }
    }
}
