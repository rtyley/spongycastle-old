package org.bouncycastle.cavp.test;

public interface DigestProcessor
{
    void update(byte[] msg);

    byte[] digest();
}
