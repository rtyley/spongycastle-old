package org.bouncycastle.crypto.signers;

import java.nio.ByteBuffer;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.NTRUSigningParameters;
import org.bouncycastle.crypto.params.NTRUSigningPrivateKeyParameters;
import org.bouncycastle.crypto.params.NTRUSigningPublicKeyParameters;
import org.bouncycastle.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.math.ntru.polynomial.Polynomial;

/**
 * Signs, verifies data and generates key pairs.
 */
public class NTRUSigner {
    private NTRUSigningParameters params;
    private Digest hashAlg;
    private AsymmetricCipherKeyPair signingKeyPair;
    private NTRUSigningPublicKeyParameters verificationKey;
    
    /**
     * Constructs a new instance with a set of signature parameters.
     * @param params signature parameters
     */
    public NTRUSigner(NTRUSigningParameters params) {
        this.params = params;
    }

    /**
     * Resets the engine for signing a message.
     * @param kp
     */
    public void initSign(AsymmetricCipherKeyPair kp) {
        this.signingKeyPair = kp;
        hashAlg = params.hashAlg;
        hashAlg.reset();
    }

    /**
     * Adds data to sign or verify.
     * @param m
     */
    public void update(byte[] m) {
        if (hashAlg == null)
            throw new IllegalStateException("Call initSign or initVerify first!");
        
        hashAlg.update(m, 0, m.length);
    }
    
    /**
     * Adds data to sign and computes a signature over this data and any data previously added via {@link #update(byte[])}.
     * @param m
     * @return a signature
     * @throws IllegalStateException if <code>initSign</code> was not called
     */
    public byte[] sign(byte[] m) {
        if (hashAlg==null || signingKeyPair==null)
            throw new IllegalStateException("Call initSign first!");
        
        byte[] msgHash = new byte[hashAlg.getDigestSize()];

        hashAlg.update(m, 0, m.length);

        hashAlg.doFinal(msgHash, 0);
        return signHash(msgHash, signingKeyPair);
    }
    
    /**
     * Signs a message.<br/>
     * This is a "one stop" method and does not require <code>initSign</code> to be called. Only the message supplied via
     * the parameter <code>m</code> is signed, regardless of prior calls to {@link #update(byte[])}.
     * @param m the message to sign
     * @param kp a key pair (the public key is needed to ensure there are no signing failures)
     * @return a signature
     */
    public byte[] sign(byte[] m, AsymmetricCipherKeyPair kp) {
            // EESS directly passes the message into the MRGM (message representative
            // generation method). Since that is inefficient for long messages, we work
            // with the hash of the message.
            Digest hashAlg = params.hashAlg;

            byte[] msgHash = new byte[hashAlg.getDigestSize()];

            hashAlg.update(m, 0, m.length);

            hashAlg.doFinal(msgHash, 0);
            return signHash(msgHash, kp);
    }
    
    private byte[] signHash(byte[] msgHash, AsymmetricCipherKeyPair kp) {
        int r = 0;
        IntegerPolynomial s;
        IntegerPolynomial i;

        NTRUSigningPublicKeyParameters kPub = (NTRUSigningPublicKeyParameters)kp.getPublic();
        do {
            r++;
            if (r > params.signFailTolerance)
                throw new IllegalStateException("Signing failed: too many retries (max=" + params.signFailTolerance + ")");
            i = createMsgRep(msgHash, r);
            s = sign(i, kp);
        } while (!verify(i, s, kPub.h));

        byte[] rawSig = s.toBinary(params.q);
        ByteBuffer sbuf = ByteBuffer.allocate(rawSig.length + 4);
        sbuf.put(rawSig);
        sbuf.putInt(r);
        return sbuf.array();
    }
    
    private IntegerPolynomial sign(IntegerPolynomial i, AsymmetricCipherKeyPair kp) {
        int N = params.N;
        int q = params.q;
        int perturbationBases = params.B;
        
        NTRUSigningPrivateKeyParameters kPriv = (NTRUSigningPrivateKeyParameters)kp.getPrivate();
        NTRUSigningPublicKeyParameters kPub = (NTRUSigningPublicKeyParameters)kp.getPublic();
        
        IntegerPolynomial s = new IntegerPolynomial(N);
        int iLoop = perturbationBases;
        while (iLoop >= 1) {
            Polynomial f = kPriv.getBasis(iLoop).f;
            Polynomial fPrime = kPriv.getBasis(iLoop).fPrime;
            
            IntegerPolynomial y = f.mult(i);
            y.div(q);
            y = fPrime.mult(y);
            
            IntegerPolynomial x = fPrime.mult(i);
            x.div(q);
            x = f.mult(x);

            IntegerPolynomial si = y;
            si.sub(x);
            s.add(si);
            
            IntegerPolynomial hi = kPriv.getBasis(iLoop).h.clone();
            if (iLoop > 1)
                hi.sub(kPriv.getBasis(iLoop-1).h);
            else
                hi.sub(kPub.h);
            i = si.mult(hi, q);
            
            iLoop--;
        }
        
        Polynomial f = kPriv.getBasis(0).f;
        Polynomial fPrime = kPriv.getBasis(0).fPrime;
        
        IntegerPolynomial y = f.mult(i);
        y.div(q);
        y = fPrime.mult(y);
        
        IntegerPolynomial x = fPrime.mult(i);
        x.div(q);
        x = f.mult(x);

        y.sub(x);
        s.add(y);
        s.modPositive(q);
        return s;
    }
    
    /**
     * Resets the engine for verifying a signature.
     * @param pub the public key to use in the {@link #verify(byte[])} step
     */
    public void initVerify(NTRUSigningPublicKeyParameters pub) {
        verificationKey = pub;

            hashAlg = params.hashAlg;

        hashAlg.reset();
    }

    /**
     * Verifies a signature for any data previously added via {@link #update(byte[])}.
     * @param sig a signature
     * @return whether the signature is valid
     * @throws IllegalStateException if <code>initVerify</code> was not called
     */
    public boolean verify(byte[] sig) {
        if (hashAlg==null || verificationKey==null)
            throw new IllegalStateException("Call initVerify first!");

        byte[] msgHash = new byte[hashAlg.getDigestSize()];

        hashAlg.doFinal(msgHash, 0);

        return verifyHash(msgHash, sig, verificationKey);
    }
    
    /**
     * Verifies a signature.<br/>
     * This is a "one stop" method and does not require <code>initVerify</code> to be called. Only the message supplied via
     * the parameter <code>m</code> is signed, regardless of prior calls to {@link #update(byte[])}.
     * @param m the message to sign
     * @param sig the signature
     * @param pub a public key
     * @return whether the signature is valid
     */
    public boolean verify(byte[] m, byte[] sig, NTRUSigningPublicKeyParameters pub) {
        Digest hashAlg = params.hashAlg;

        hashAlg.update(m, 0, m.length);

        byte[] msgHash = new byte[hashAlg.getDigestSize()];

        hashAlg.doFinal(msgHash, 0);
        return verifyHash(msgHash, sig, pub);
    }
    
    private boolean verifyHash(byte[] msgHash, byte[] sig, NTRUSigningPublicKeyParameters pub) {
        ByteBuffer sbuf = ByteBuffer.wrap(sig);
        byte[] rawSig = new byte[sig.length - 4];
        sbuf.get(rawSig);
        IntegerPolynomial s = IntegerPolynomial.fromBinary(rawSig, params.N, params.q);
        int r = sbuf.getInt();
        return verify(createMsgRep(msgHash, r), s, pub.h);
    }
    
    private boolean verify(IntegerPolynomial i, IntegerPolynomial s, IntegerPolynomial h) {
        int q = params.q;
        double normBoundSq = params.normBoundSq;
        double betaSq = params.betaSq;
        
        IntegerPolynomial t = h.mult(s, q);
        t.sub(i);
        long centeredNormSq = (long)(s.centeredNormSq(q) + betaSq * t.centeredNormSq(q));
        return centeredNormSq <= normBoundSq;
    }
    
    IntegerPolynomial createMsgRep(byte[] msgHash, int r) {
        int N = params.N;
        int q = params.q;
        
        int c = 31 - Integer.numberOfLeadingZeros(q);
        int B = (c+7) / 8;
        IntegerPolynomial i = new IntegerPolynomial(N);
        
        ByteBuffer cbuf = ByteBuffer.allocate(msgHash.length + 4);
        cbuf.put(msgHash);
        cbuf.putInt(r);
        NTRUSignerPrng prng = new NTRUSignerPrng(cbuf.array(), params.hashAlg);
        
        for (int t=0; t<N; t++) {
            byte[] o = prng.nextBytes(B);
            int hi = o[o.length-1];
            hi >>= 8*B-c;
            hi <<= 8*B-c;
            o[o.length-1] = (byte)hi;
            
            ByteBuffer obuf = ByteBuffer.allocate(4);
            obuf.put(o);
            obuf.rewind();
            // reverse byte order so it matches the endianness of java ints
            i.coeffs[t] = Integer.reverseBytes(obuf.getInt());
        }
        return i;
    }
}
