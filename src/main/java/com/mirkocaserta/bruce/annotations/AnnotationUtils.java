package com.mirkocaserta.bruce.annotations;

public final class AnnotationUtils {
    public static final String DEFAULT = "DEFAULT";

    private AnnotationUtils() {
        // utility class, users can't make new instances
    }

    public static boolean isDefault(final String s) {
        return DEFAULT.equals(s);
    }
}
