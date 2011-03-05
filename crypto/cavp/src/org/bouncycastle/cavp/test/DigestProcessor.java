package org.spongycastle.cavp.test;

public interface DigestProcessor
{
    void update(byte[] msg);

    byte[] digest();
}
