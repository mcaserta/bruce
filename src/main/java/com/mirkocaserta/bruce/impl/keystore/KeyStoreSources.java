package com.mirkocaserta.bruce.impl.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.IntPredicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class KeyStoreSources {

    /**
     * Matches a URL-style scheme ({@code scheme://}). A Windows drive letter
     * like {@code C:\} or {@code C:/} does not match because it lacks the
     * double slash.
     */
    private static final Pattern SCHEME = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*)://");

    /** Separates a URL scheme from its authority. */
    private static final String AUTHORITY_START = "://";

    /** Characters that end an authority: path, query and fragment delimiters. */
    private static final String AUTHORITY_END = "/?#";


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
     * {@code text}. The URL scans alone miss them when the location contains
     * whitespace or shows up in a non-URL form (for example as a file path).
     */
    static String redact(String text, String location) {
        if (text == null) {
            return null;
        }
        for (String secret : secrets(location)) {
            text = text.replace(secret, "***");
        }
        String redacted = redactUserInfo(text);
        // Presigned object-store URLs and ?token= style links carry their
        // credentials in the query string.
        redacted = redactAfter(redacted, '?', c -> isSpace(c) || c == '?' || c == '#', c -> isSpace(c) || c == '#');
        return redactAfter(redacted, '#', c -> isSpace(c) || c == '#', KeyStoreSources::isSpace);
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
        Span span = findUserInfo(location, 0);
        if (span == null) {
            return null;
        }
        String userInfo = location.substring(span.start(), span.end() - 1);
        return userInfo.isEmpty() ? null : userInfo;
    }

    /** Replaces every userinfo found by {@link #findUserInfo} with {@code ***@}. */
    private static String redactUserInfo(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int copied = 0;
        for (Span span = findUserInfo(text, 0); span != null; span = findUserInfo(text, span.end())) {
            out.append(text, copied, span.start()).append("***@");
            copied = span.end();
        }
        return copied == 0 ? text : out.append(text, copied, text.length()).toString();
    }

    /**
     * Finds the first userinfo at or after {@code from}: the text right after
     * a {@code ://}, up to and including the last {@code @} before the next
     * path, query or fragment delimiter (or the end of the text), so a raw
     * {@code @} inside a password is covered too. Anything else, whitespace
     * included, is part of the run. When the run after a {@code ://} has no
     * {@code @}, the search moves on to the next {@code ://}.
     *
     * <p>Runs in linear time: a run contains no {@code /}, so the next
     * {@code ://} starts at the earliest on the last character of the current
     * run, and runs never overlap.</p>
     *
     * @return the span, {@code @} included, or {@code null} if there is none
     */
    private static Span findUserInfo(String text, int from) {
        int separator = text.indexOf(AUTHORITY_START, from);
        while (separator >= 0) {
            int start = separator + AUTHORITY_START.length();
            int lastAt = -1;
            for (int i = start; i < text.length() && AUTHORITY_END.indexOf(text.charAt(i)) < 0; i++) {
                if (text.charAt(i) == '@') {
                    lastAt = i;
                }
            }
            if (lastAt >= 0) {
                return new Span(start, lastAt + 1);
            }
            separator = text.indexOf(AUTHORITY_START, separator + 1);
        }
        return null;
    }

    /**
     * Replaces the value after {@code marker} in every URL of the text with
     * {@code ***}. A URL starts at {@code ://} and runs up to the first
     * character matching {@code runEnd}; when that character is
     * {@code marker}, everything after it up to the first character matching
     * {@code valueEnd} (or the end of the text) is the value. The marker
     * itself is kept, and an empty value is replaced too.
     *
     * <p>Runs in linear time: a {@code ://} inside a run that does not end
     * in the marker would end at the same character, so the search resumes
     * after the run instead of rescanning it.</p>
     */
    private static String redactAfter(String text, char marker, IntPredicate runEnd, IntPredicate valueEnd) {
        StringBuilder out = new StringBuilder(text.length());
        int copied = 0;
        int separator = text.indexOf(AUTHORITY_START);
        while (separator >= 0) {
            int i = separator + AUTHORITY_START.length();
            while (i < text.length() && !runEnd.test(text.charAt(i))) {
                i++;
            }
            if (i < text.length() && text.charAt(i) == marker) {
                out.append(text, copied, i + 1).append("***");
                i++;
                while (i < text.length() && !valueEnd.test(text.charAt(i))) {
                    i++;
                }
                copied = i;
            }
            separator = text.indexOf(AUTHORITY_START, i);
        }
        return copied == 0 ? text : out.append(text, copied, text.length()).toString();
    }

    /** Whitespace as the regex class {@code \s} defines it. */
    private static boolean isSpace(int c) {
        return c == ' ' || c == '\t' || c == '\n' || c == 0x0B || c == '\f' || c == '\r';
    }

    /** A range of text, {@code end} exclusive. */
    private record Span(int start, int end) {
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
