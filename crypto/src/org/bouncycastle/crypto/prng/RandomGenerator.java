package org.bouncycastle.crypto.prng;

/**
 * Generic interface for objects generating random bytes.
 */
public interface RandomGenerator
{
    void addSeedMaterial(byte[] inSeed);

    void addSeedMaterial(long rSeed);

    void nextBytes(byte[] bytes);
}
