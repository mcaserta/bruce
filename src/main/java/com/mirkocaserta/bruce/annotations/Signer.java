package com.mirkocaserta.bruce.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static com.mirkocaserta.bruce.annotations.AnnotationUtils.DEFAULT;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Signer {
    PrivateKey privateKey();

    String algorithm();

    String provider() default DEFAULT;

    String charset() default DEFAULT;

    String encoding() default DEFAULT;
}
