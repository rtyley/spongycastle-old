package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.Arrays;

public abstract class JDKAlgorithmParameters
    extends AlgorithmParametersSpi
{
    protected boolean isASN1FormatString(String format)
    {
        return format == null || format.equals("ASN.1");
    }

    protected AlgorithmParameterSpec engineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == null)
        {
            throw new NullPointerException("argument to getParameterSpec must not be null");
        }

        return localEngineGetParameterSpec(paramSpec);
    }

    protected abstract AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
        throws InvalidParameterSpecException;

    public static class IVAlgorithmParameters
        extends JDKAlgorithmParameters
    {
        private int blockSize;

        public IVAlgorithmParameters(int blockSize)
        {
            this.blockSize = blockSize;
        }

        public IVAlgorithmParameters()
        {
            this.blockSize = 8;
        }

        private byte[]  iv;

        protected byte[] engineGetEncoded() 
            throws IOException
        {
            return engineGetEncoded("ASN.1");
        }

        protected byte[] engineGetEncoded(
            String format) 
            throws IOException
        {
            if (isASN1FormatString(format))
            {
                 return new DEROctetString(engineGetEncoded("RAW")).getEncoded();
            }
            
            if (format.equals("RAW"))
            {
                return Arrays.clone(iv);
            }

            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec) 
            throws InvalidParameterSpecException
        {
            if (paramSpec == IvParameterSpec.class)
            {
                return new IvParameterSpec(iv);
            }

            throw new InvalidParameterSpecException("unknown parameter spec passed to IV parameters object.");
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec) 
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof IvParameterSpec))
            {
                throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
            }

            this.iv = ((IvParameterSpec)paramSpec).getIV();
        }

        protected void engineInit(
            byte[] params) 
            throws IOException
        {
            //
            // check that we don't have a DER encoded octet string
            //
            if ((params.length % 8) != 0
                    && params[0] == 0x04 && params[1] == params.length - 2)
            {
                ASN1OctetString oct = (ASN1OctetString)ASN1Primitive.fromByteArray(params);

                params = oct.getOctets();
            }

            this.iv = Arrays.clone(params);
        }

        protected void engineInit(
            byte[] params,
            String format) 
            throws IOException
        {
            if (isASN1FormatString(format))
            {
                try
                {
                    ASN1Primitive object = ASN1Primitive.fromByteArray(params);

                    if (object instanceof ASN1OctetString)
                    {
                        ASN1OctetString oct = (ASN1OctetString)object;

                        this.iv = Arrays.clone(oct.getOctets());
                    }
                    else if (object instanceof ASN1Null)
                    {
                        // assume an iv of zeros
                        this.iv = new byte[blockSize];
                    }
                    else
                    {
                        throw new IOException("unknown encoding for parameters");
                    }
                }
                catch (IOException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new IOException("Exception decoding: " + e);
                }
                
                return;
            }

            if (format.equals("RAW"))
            {
                engineInit(params);
                return;
            }

            throw new IOException("Unknown parameters format in IV parameters object");
        }

        protected String engineToString() 
        {
            return "IV Parameters";
        }
    }


    public static class PBKDF2
        extends JDKAlgorithmParameters
    {
        PBKDF2Params params;

        protected byte[] engineGetEncoded()
        {
            try
            {
                return params.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new RuntimeException("Oooops! " + e.toString());
            }
        }

        protected byte[] engineGetEncoded(
            String format)
        {
            if (isASN1FormatString(format))
            {
                return engineGetEncoded();
            }

            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == PBEParameterSpec.class)
            {
                return new PBEParameterSpec(params.getSalt(),
                                params.getIterationCount().intValue());
            }

            throw new InvalidParameterSpecException("unknown parameter spec passed to PKCS12 PBE parameters object.");
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PBEParameterSpec))
            {
                throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PKCS12 PBE parameters algorithm parameters object");
            }

            PBEParameterSpec    pbeSpec = (PBEParameterSpec)paramSpec;

            this.params = new PBKDF2Params(pbeSpec.getSalt(),
                                pbeSpec.getIterationCount());
        }

        protected void engineInit(
            byte[] params)
            throws IOException
        {
            this.params = PBKDF2Params.getInstance(ASN1Primitive.fromByteArray(params));
        }

        protected void engineInit(
            byte[] params,
            String format)
            throws IOException
        {
            if (isASN1FormatString(format))
            {
                engineInit(params);
                return;
            }

            throw new IOException("Unknown parameters format in PWRIKEK parameters object");
        }

        protected String engineToString()
        {
            return "PBKDF2 Parameters";
        }
    }

    public static class PKCS12PBE
        extends JDKAlgorithmParameters
    {
        PKCS12PBEParams params;

        protected byte[] engineGetEncoded() 
        {
            try
            {
                return params.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new RuntimeException("Oooops! " + e.toString());
            }
        }

        protected byte[] engineGetEncoded(
            String format) 
        {
            if (isASN1FormatString(format))
            {
                return engineGetEncoded();
            }

            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec) 
            throws InvalidParameterSpecException
        {
            if (paramSpec == PBEParameterSpec.class)
            {
                return new PBEParameterSpec(params.getIV(),
                                params.getIterations().intValue());
            }

            throw new InvalidParameterSpecException("unknown parameter spec passed to PKCS12 PBE parameters object.");
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec) 
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PBEParameterSpec))
            {
                throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PKCS12 PBE parameters algorithm parameters object");
            }

            PBEParameterSpec    pbeSpec = (PBEParameterSpec)paramSpec;

            this.params = new PKCS12PBEParams(pbeSpec.getSalt(),
                                pbeSpec.getIterationCount());
        }

        protected void engineInit(
            byte[] params) 
            throws IOException
        {
            this.params = PKCS12PBEParams.getInstance(ASN1Primitive.fromByteArray(params));
        }

        protected void engineInit(
            byte[] params,
            String format) 
            throws IOException
        {
            if (isASN1FormatString(format))
            {
                engineInit(params);
                return;
            }

            throw new IOException("Unknown parameters format in PKCS12 PBE parameters object");
        }

        protected String engineToString() 
        {
            return "PKCS12 PBE Parameters";
        }
    }

    public static class IES
        extends JDKAlgorithmParameters
    {
        IESParameterSpec     currentSpec;

        /**
         * in the absence of a standard way of doing it this will do for
         * now...
         */
        protected byte[] engineGetEncoded() 
        {
            try
            {
                ASN1EncodableVector v = new ASN1EncodableVector();

                v.add(new DEROctetString(currentSpec.getDerivationV()));
                v.add(new DEROctetString(currentSpec.getEncodingV()));
                v.add(new DERInteger(currentSpec.getMacKeySize()));

                return new DERSequence(v).getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new RuntimeException("Error encoding IESParameters");
            }
        }

        protected byte[] engineGetEncoded(
            String format) 
        {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509"))
            {
                return engineGetEncoded();
            }

            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec) 
            throws InvalidParameterSpecException
        {
            if (paramSpec == IESParameterSpec.class)
            {
                return currentSpec;
            }

            throw new InvalidParameterSpecException("unknown parameter spec passed to ElGamal parameters object.");
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec) 
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof IESParameterSpec))
            {
                throw new InvalidParameterSpecException("IESParameterSpec required to initialise a IES algorithm parameters object");
            }

            this.currentSpec = (IESParameterSpec)paramSpec;
        }

        protected void engineInit(
            byte[] params) 
            throws IOException
        {
            try
            {
                ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(params);

                this.currentSpec = new IESParameterSpec(
                                        ((ASN1OctetString)s.getObjectAt(0)).getOctets(),
                                        ((ASN1OctetString)s.getObjectAt(0)).getOctets(),
                                        ((DERInteger)s.getObjectAt(0)).getValue().intValue());
            }
            catch (ClassCastException e)
            {
                throw new IOException("Not a valid IES Parameter encoding.");
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                throw new IOException("Not a valid IES Parameter encoding.");
            }
        }

        protected void engineInit(
            byte[] params,
            String format) 
            throws IOException
        {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509"))
            {
                engineInit(params);
            }
            else
            {
                throw new IOException("Unknown parameter format " + format);
            }
        }

        protected String engineToString() 
        {
            return "IES Parameters";
        }
    }
}
