package com.mirkocaserta.bruce;

public class BruceException extends RuntimeException {

    public BruceException(String message, Exception e) {
        super(message, e);
    }

    public BruceException(String message) {
        super(message);
    }

}
