package com.mirkocaserta.bruce.impl.keystore;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;

/**
 * Loads keystores over https. Plain http is deliberately not supported: a
 * network attacker could swap the keystore in transit.
 *
 * <p>Connections use fixed connect and read timeouts so a slow or stalled
 * server cannot hang the caller forever. Redirects keep the JDK defaults,
 * which follow https redirects but refuse to switch to a different protocol.
 */
final class HttpsKeyStoreSource implements KeyStoreSource {

    static final int CONNECT_TIMEOUT_MILLIS = 10_000;
    static final int READ_TIMEOUT_MILLIS = 30_000;

    private static final String PREFIX = "https://";

    @FunctionalInterface
    interface ConnectionFactory {
        URLConnection open(URL url) throws IOException;
    }

    private final ConnectionFactory connectionFactory;

    HttpsKeyStoreSource() {
        this(URL::openConnection);
    }

    HttpsKeyStoreSource(ConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    @Override
    public boolean supports(String location) {
        return location != null && location.regionMatches(true, 0, PREFIX, 0, PREFIX.length());
    }

    @Override
    public InputStream open(String location) throws IOException {
        URLConnection connection = connect(location);
        try {
            return connection.getInputStream();
        } catch (IOException e) {
            throw KeyStoreSources.sanitize(e, location);
        }
    }

    /**
     * Creates the connection and configures it, without connecting yet.
     */
    URLConnection connect(String location) throws IOException {
        URL url;
        try {
            url = URI.create(location).toURL();
        } catch (IllegalArgumentException | MalformedURLException e) {
            // the JDK message echoes the raw location, so it is not kept as the cause
            throw new IOException("invalid keystore location: " + KeyStoreSources.redact(location));
        }
        URLConnection connection = connectionFactory.open(url);
        if (!(connection instanceof HttpsURLConnection)) {
            throw new IOException("expected an https connection for keystore location: "
                    + KeyStoreSources.redact(location));
        }
        connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
        connection.setReadTimeout(READ_TIMEOUT_MILLIS);
        return connection;
    }
}
