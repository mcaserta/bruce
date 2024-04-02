package com.mirkocaserta.bruce.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static com.mirkocaserta.bruce.annotations.AnnotationUtils.DEFAULT;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Digester {

    String algorithm();

    String provider() default DEFAULT;

    String encoding() default DEFAULT;

    String charsetName() default DEFAULT;
}
