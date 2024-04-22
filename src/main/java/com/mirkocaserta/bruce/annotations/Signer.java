package com.mirkocaserta.bruce.annotations;

import static com.mirkocaserta.bruce.annotations.AnnotationUtils.DEFAULT;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Signer {
  PrivateKey privateKey();

  String algorithm();

  String provider() default DEFAULT;

  String charset() default DEFAULT;

  String encoding() default DEFAULT;
}
