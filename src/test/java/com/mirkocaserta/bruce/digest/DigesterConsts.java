package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.util.Hex;

public final class DigesterConsts {

    private static final Hex.Decoder DECODER = Hex.getDecoder();

    public static final byte[] MESSAGE_SHA1 = DECODER.decode("6f9b9af3cd6e8b8a73c2cdced37fe9f59226e27d");
    public static final byte[] EMPTY_SHA1 = DECODER.decode("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    public static final byte[] MESSAGE_MD5 = DECODER.decode("78e731027d8fd50ed642340b7c9a63b3");
    public static final byte[] EMPTY_MD5 = DECODER.decode("d41d8cd98f00b204e9800998ecf8427e");

    private DigesterConsts() {
    }
}

