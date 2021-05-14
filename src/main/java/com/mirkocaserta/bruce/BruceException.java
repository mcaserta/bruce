package com.mirkocaserta.bruce;

/**
 * An exception specific to Bruce.
 */
public class BruceException extends RuntimeException {

    /**
     * Builds a Bruce specific exception.
     *
     * @param message the exception message
     * @param e the originating exception
     */
    public BruceException(String message, Exception e) {
        super(message, e);
    }

    /**
     * Builds a Bruce specific exception.
     *
     * @param message the exception message
     */
    public BruceException(String message) {
        super(message);
    }

}
