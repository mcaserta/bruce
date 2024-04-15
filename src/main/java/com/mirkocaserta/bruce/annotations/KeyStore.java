package com.mirkocaserta.bruce.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static com.mirkocaserta.bruce.annotations.AnnotationUtils.DEFAULT;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.ANNOTATION_TYPE)
public @interface KeyStore {
    String location();

    char[] password();

    String type() default DEFAULT;

    String provider() default DEFAULT;
}
