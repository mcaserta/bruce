package com.mirkocaserta.bruce.impl.keystore;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;

/**
 * Caps how many bytes a keystore download may deliver and how long it may
 * take in total. A per-read socket timeout alone lets a server trickle one
 * byte at a time forever, or stream until the heap runs out.
 */
final class BoundedInputStream extends FilterInputStream {

    private final long maxBytes;
    private final long deadlineNanos;
    private long count;

    BoundedInputStream(InputStream in, long maxBytes, Duration timeout) {
        super(in);
        this.maxBytes = maxBytes;
        this.deadlineNanos = System.nanoTime() + timeout.toNanos();
    }

    @Override
    public int read() throws IOException {
        checkDeadline();
        int b = super.read();
        if (b >= 0) {
            account(1);
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        checkDeadline();
        int n = super.read(b, off, len);
        if (n > 0) {
            account(n);
        }
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        checkDeadline();
        long skipped = super.skip(n);
        if (skipped > 0) {
            account(skipped);
        }
        return skipped;
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    private void account(long n) throws IOException {
        count += n;
        if (count > maxBytes) {
            throw new IOException("keystore exceeds the maximum size of " + maxBytes + " bytes");
        }
    }

    private void checkDeadline() throws IOException {
        if (System.nanoTime() - deadlineNanos > 0) {
            throw new IOException("keystore download took longer than the allowed time");
        }
    }
}
