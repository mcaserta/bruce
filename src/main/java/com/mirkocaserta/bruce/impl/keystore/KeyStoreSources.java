package com.mirkocaserta.bruce.impl.keystore;

import java.io.IOException;
import java.io.InputStream;
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
                    redact(location)));
        }
        for (KeyStoreSource source : SOURCES) {
            if (source.supports(location)) {
                try {
                    return source.open(location);
                } catch (IOException e) {
                    throw sanitize(e, location);
                }
            }
        }
        String scheme = scheme(location);
        if (scheme != null) {
            throw new IOException(String.format(
                    "unsupported keystore location scheme: %s (supported: classpath:, file:, https://): location=%s",
                    scheme, redact(location)));
        }
        throw new IOException("unsupported keystore location: " + redact(location));
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
     * Replaces any userinfo (for example {@code user:password@}) in the given
     * text with {@code ***@}, so it is safe to put in error messages.
     */
    static String redact(String text) {
        return text == null ? null : USER_INFO.matcher(text).replaceAll("***@");
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
        String userInfo = userInfo(location);
        if (userInfo == null || !leaks(e, userInfo)) {
            return e;
        }
        String message = redact(String.valueOf(e.getMessage()).replace(userInfo + "@", "***@"));
        IOException sanitized = new IOException(String.format("%s: %s (location=%s)",
                e.getClass().getName(), message, redact(location)));
        sanitized.setStackTrace(e.getStackTrace());
        return sanitized;
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

    private static boolean leaks(Throwable t, String userInfo) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c.toString().contains(userInfo)) {
                return true;
            }
        }
        return false;
    }
}
