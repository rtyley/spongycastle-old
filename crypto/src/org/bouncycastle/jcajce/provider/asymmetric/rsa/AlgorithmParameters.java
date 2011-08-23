package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

public abstract class AlgorithmParameters
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
        extends AlgorithmParameters
    {
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
                ASN1OctetString oct = ASN1OctetString.getInstance(params);

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
                    ASN1OctetString oct = ASN1OctetString.getInstance(params);

                    engineInit(oct.getOctets());
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

    public static class OAEP
        extends AlgorithmParameters
    {
        OAEPParameterSpec currentSpec;
    
        /**
         * Return the PKCS#1 ASN.1 structure RSAES-OAEP-params.
         */
        protected byte[] engineGetEncoded() 
        {
            AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(
                                                            JCEDigestUtil.getOID(currentSpec.getDigestAlgorithm()),
                                                            new DERNull());
            MGF1ParameterSpec mgfSpec = (MGF1ParameterSpec)currentSpec.getMGFParameters();
            AlgorithmIdentifier maskGenAlgorithm = new AlgorithmIdentifier(
                                                            PKCSObjectIdentifiers.id_mgf1,
                                                            new AlgorithmIdentifier(JCEDigestUtil.getOID(mgfSpec.getDigestAlgorithm()), new DERNull()));
            PSource.PSpecified      pSource = (PSource.PSpecified)currentSpec.getPSource();
            AlgorithmIdentifier pSourceAlgorithm = new AlgorithmIdentifier(
                                                            PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(pSource.getValue()));
            RSAESOAEPparams oaepP = new RSAESOAEPparams(hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm);
    
            try
            {
                return oaepP.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new RuntimeException("Error encoding OAEPParameters");
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
            if (paramSpec == OAEPParameterSpec.class && currentSpec != null)
            {
                return currentSpec;
            }
    
            throw new InvalidParameterSpecException("unknown parameter spec passed to OAEP parameters object.");
        }
    
        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof OAEPParameterSpec))
            {
                throw new InvalidParameterSpecException("OAEPParameterSpec required to initialise an OAEP algorithm parameters object");
            }
    
            this.currentSpec = (OAEPParameterSpec)paramSpec;
        }
    
        protected void engineInit(
            byte[] params) 
            throws IOException
        {
            try
            {
                RSAESOAEPparams oaepP = RSAESOAEPparams.getInstance(params);

                currentSpec = new OAEPParameterSpec(
                                       oaepP.getHashAlgorithm().getAlgorithm().getId(),
                                       oaepP.getMaskGenAlgorithm().getAlgorithm().getId(), 
                                       new MGF1ParameterSpec(AlgorithmIdentifier.getInstance(oaepP.getMaskGenAlgorithm().getParameters()).getAlgorithm().getId()),
                                       new PSource.PSpecified(ASN1OctetString.getInstance(oaepP.getPSourceAlgorithm().getParameters()).getOctets()));
            }
            catch (ClassCastException e)
            {
                throw new IOException("Not a valid OAEP Parameter encoding.");
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                throw new IOException("Not a valid OAEP Parameter encoding.");
            }
        }
    
        protected void engineInit(
            byte[] params,
            String format)
            throws IOException
        {
            if (format.equalsIgnoreCase("X.509")
                    || format.equalsIgnoreCase("ASN.1"))
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
            return "OAEP Parameters";
        }
    }
    
    public static class PSS
        extends AlgorithmParameters
    {  
        PSSParameterSpec currentSpec;
    
        /**
         * Return the PKCS#1 ASN.1 structure RSASSA-PSS-params.
         */
        protected byte[] engineGetEncoded() 
            throws IOException
        {
            PSSParameterSpec pssSpec = currentSpec;
            AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(
                                                JCEDigestUtil.getOID(pssSpec.getDigestAlgorithm()),
                                                new DERNull());
            MGF1ParameterSpec mgfSpec = (MGF1ParameterSpec)pssSpec.getMGFParameters();
            AlgorithmIdentifier maskGenAlgorithm = new AlgorithmIdentifier(
                                                PKCSObjectIdentifiers.id_mgf1,
                                                new AlgorithmIdentifier(JCEDigestUtil.getOID(mgfSpec.getDigestAlgorithm()), new DERNull()));
            RSASSAPSSparams pssP = new RSASSAPSSparams(hashAlgorithm, maskGenAlgorithm, new ASN1Integer(pssSpec.getSaltLength()), new ASN1Integer(pssSpec.getTrailerField()));
            
            return pssP.getEncoded("DER");
        }
    
        protected byte[] engineGetEncoded(
            String format)
            throws IOException
        {
            if (format.equalsIgnoreCase("X.509")
                    || format.equalsIgnoreCase("ASN.1"))
            {
                return engineGetEncoded();
            }
    
            return null;
        }
    
        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == PSSParameterSpec.class && currentSpec != null)
            {
                return currentSpec;
            }
    
            throw new InvalidParameterSpecException("unknown parameter spec passed to PSS parameters object.");
        }
    
        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PSSParameterSpec))
            {
                throw new InvalidParameterSpecException("PSSParameterSpec required to initialise an PSS algorithm parameters object");
            }
    
            this.currentSpec = (PSSParameterSpec)paramSpec;
        }
    
        protected void engineInit(
            byte[] params) 
            throws IOException
        {
            try
            {
                RSASSAPSSparams pssP = RSASSAPSSparams.getInstance(params);

                currentSpec = new PSSParameterSpec(
                                       pssP.getHashAlgorithm().getAlgorithm().getId(), 
                                       pssP.getMaskGenAlgorithm().getAlgorithm().getId(), 
                                       new MGF1ParameterSpec(AlgorithmIdentifier.getInstance(pssP.getMaskGenAlgorithm().getParameters()).getAlgorithm().getId()),
                                       pssP.getSaltLength().intValue(),
                                       pssP.getTrailerField().intValue());
            }
            catch (ClassCastException e)
            {
                throw new IOException("Not a valid PSS Parameter encoding.");
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                throw new IOException("Not a valid PSS Parameter encoding.");
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
            return "PSS Parameters";
        }
    }
}
