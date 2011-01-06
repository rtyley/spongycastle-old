package org.bouncycastle.crypto.tls;

public class KeyExchangeAlgorithm
{
    /*
     * Note that the values here are implementation-specific and arbitrary.
     * It is recommended not to depend on the particular values (e.g. serialization).
     */
    public static final int RSA = 1;
//    public static final int RSA_EXPORT = 2;
    public static final int DHE_DSS = 3;
//    public static final int DHE_DSS_EXPORT = 4;
    public static final int DHE_RSA = 5;
//    public static final int DHE_RSA_EXPORT = 6;
    public static final int DH_DSS = 7;
    public static final int DH_RSA = 8;
//    public static final int DH_anon = 9;
    public static final int SRP = 10;
    public static final int SRP_DSS = 11;
    public static final int SRP_RSA = 12;
    public static final int ECDH_ECDSA = 13;
    public static final int ECDHE_ECDSA = 14;
    public static final int ECDH_RSA = 15;
    public static final int ECDHE_RSA = 16;
//    public static final int ECDH_anon = 17;
}
