package com.mirkocaserta.bruce.api.annotations;

import com.mirkocaserta.bruce.Encoding;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Digester {
  String algorithm();

  String provider() default "";

  Encoding encoding() default Encoding.BASE64;

  String charsetName() default "UTF-8";

  Class<?> outputType() default String.class;
}
