package com.mirkocaserta.bruce.impl.keystore;

import java.io.IOException;
import java.io.InputStream;

/**
 * Strategy for opening a keystore input stream from a location.
 */
interface KeyStoreSource {

    boolean supports(String location);

    InputStream open(String location) throws IOException;
}

