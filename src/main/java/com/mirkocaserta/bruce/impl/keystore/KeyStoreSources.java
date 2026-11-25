package com.mirkocaserta.bruce.impl.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class KeyStoreSources {

    /**
     * Matches a URL-style scheme ({@code scheme://}). A Windows drive letter
     * like {@code C:\} or {@code C:/} does not match because it lacks the
     * double slash.
     */
    private static final Pattern SCHEME = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*)://");

    /**
     * Matches the userinfo part of an authority, up to the last {@code @}
     * before the path, query or fragment, so a raw {@code @} inside a
     * password is covered too.
     */
    private static final Pattern USER_INFO = Pattern.compile("(?<=://)[^/?#]*@");

    /**
     * Matches the query string of a URL. Presigned object-store URLs and
     * {@code ?token=} style links carry their credentials here.
     */
    private static final Pattern QUERY = Pattern.compile("(://[^\\s?#]*)\\?[^\\s#]*");

    /** Matches the fragment of a URL. */
    private static final Pattern FRAGMENT = Pattern.compile("(://[^\\s#]*)#\\S*");

    /** Keystores are a few KB; anything this large is not one. */
    static final long MAX_KEYSTORE_BYTES = 16L * 1024 * 1024;

    /** Upper bound for a whole https download, on top of the per-read timeout. */
    static final Duration MAX_DOWNLOAD_TIME = Duration.ofMinutes(2);

    private static final List<KeyStoreSource> SOURCES = List.of(
            new ClasspathKeyStoreSource(),
            new HttpsKeyStoreSource(),
            new FileKeyStoreSource()
    );

    private KeyStoreSources() {
        // utility class
    }

    static InputStream open(String location) throws IOException {
        if ("http".equals(scheme(location))) {
            throw new IOException(String.format(
                    "plain HTTP is not supported for keystore locations, use https:// instead: location=%s",
                    redact(location, location)));
        }
        for (KeyStoreSource source : SOURCES) {
            if (source.supports(location)) {
                try {
                    InputStream in = source.open(location);
                    return source instanceof HttpsKeyStoreSource
                            ? new BoundedInputStream(in, MAX_KEYSTORE_BYTES, MAX_DOWNLOAD_TIME)
                            : in;
                } catch (IOException e) {
                    throw sanitize(e, location);
                }
            }
        }
        String scheme = scheme(location);
        if (scheme != null) {
            throw new IOException(String.format(
                    "unsupported keystore location scheme: %s (supported: classpath:, file:, https://): location=%s",
                    scheme, redact(location, location)));
        }
        throw new IOException("unsupported keystore location: " + redact(location, location));
    }

    /**
     * Returns the lower-cased URL scheme of a location written as
     * {@code scheme://...}, or {@code null} when the location has no such
     * scheme (plain paths, Windows paths, {@code classpath:} and
     * {@code file:} prefixes without a double slash).
     */
    static String scheme(String location) {
        if (location == null) {
            return null;
        }
        Matcher matcher = SCHEME.matcher(location);
        return matcher.find() ? matcher.group(1).toLowerCase(Locale.ROOT) : null;
    }

    /**
     * Replaces any userinfo (for example {@code user:password@}), query string
     * and fragment of URLs in the given text with {@code ***}, so it is safe
     * to put in error messages.
     */
    static String redact(String text) {
        return redact(text, null);
    }

    /**
     * Like {@link #redact(String)}, but first replaces the userinfo, query and
     * fragment of {@code location} literally wherever they appear in
     * {@code text}. The patterns alone miss them when the location contains
     * whitespace or shows up in a non-URL form (for example as a file path).
     */
    static String redact(String text, String location) {
        if (text == null) {
            return null;
        }
        for (String secret : secrets(location)) {
            text = text.replace(secret, "***");
        }
        String redacted = USER_INFO.matcher(text).replaceAll("***@");
        redacted = QUERY.matcher(redacted).replaceAll("$1?***");
        return FRAGMENT.matcher(redacted).replaceAll("$1#***");
    }

    /**
     * JDK errors may echo the location, userinfo included, sometimes in a form
     * the URL pattern does not catch (a {@code file://} location shows up as
     * the plain path {@code //user:password@host/...}). When the exception or
     * any of its causes contains the userinfo of the location, it is replaced
     * by an exception with a redacted message and no cause chain. Otherwise
     * the original exception is returned untouched.
     */
    static IOException sanitize(IOException e, String location) {
        List<String> secrets = secrets(location);
        if (secrets.isEmpty() || !leaks(e, secrets)) {
            return e;
        }
        String message = String.valueOf(e.getMessage());
        for (String secret : secrets) {
            message = message.replace(secret, "***");
        }
        IOException sanitized = new IOException(String.format("%s: %s (location=%s)",
                e.getClass().getName(), redact(message, location), redact(location, location)));
        sanitized.setStackTrace(e.getStackTrace());
        return sanitized;
    }

    /** The parts of a location that may carry credentials: userinfo, query and fragment. */
    private static List<String> secrets(String location) {
        List<String> secrets = new ArrayList<>();
        String userInfo = userInfo(location);
        if (userInfo != null) {
            secrets.add(userInfo);
        }
        if (location != null && scheme(location) != null) {
            addIfNotEmpty(secrets, query(location));
            int fragment = location.indexOf('#');
            addIfNotEmpty(secrets, fragment < 0 ? null : location.substring(fragment + 1));
        }
        return secrets;
    }

    /** The query string of a URL location (between {@code ?} and {@code #}), or {@code null}. */
    private static String query(String location) {
        int fragment = location.indexOf('#');
        int end = fragment < 0 ? location.length() : fragment;
        int query = location.indexOf('?');
        return query < 0 || query > end ? null : location.substring(query + 1, end);
    }

    private static void addIfNotEmpty(List<String> list, String value) {
        if (value != null && !value.isEmpty()) {
            list.add(value);
        }
    }

    private static String userInfo(String location) {
        if (location == null) {
            return null;
        }
        Matcher matcher = USER_INFO.matcher(location);
        if (!matcher.find()) {
            return null;
        }
        String userInfo = matcher.group();
        userInfo = userInfo.substring(0, userInfo.length() - 1);
        return userInfo.isEmpty() ? null : userInfo;
    }

    private static boolean leaks(Throwable t, List<String> secrets) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            String text = c.toString();
            for (String secret : secrets) {
                if (text.contains(secret)) {
                    return true;
                }
            }
        }
        return false;
    }
}
