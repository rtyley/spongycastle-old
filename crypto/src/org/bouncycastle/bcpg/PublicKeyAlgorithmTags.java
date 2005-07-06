package org.bouncycastle.bcpg;

/**
 * Public Key Algorithm tag numbers
 */
public interface PublicKeyAlgorithmTags 
{
    public static final int RSA_GENERAL = 1;       // RSA (Encrypt or Sign)
    public static final int RSA_ENCRYPT = 2;       // RSA Encrypt-Only
    public static final int RSA_SIGN = 3;          // RSA Sign-Only
    public static final int ELGAMAL_ENCRYPT = 16;  // Elgamal (Encrypt-Only), see [ELGAMAL]
    public static final int DSA = 17;              // DSA (Digital Signature Standard)
    public static final int EC = 18;               // Reserved for Elliptic Curve
    public static final int ECDSA = 19;            // Reserved for ECDSA
    public static final int ELGAMAL_GENERAL = 20;  // Elgamal (Encrypt or Sign)
    public static final int DIFFIE_HELLMAN = 21;   //  Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
}
