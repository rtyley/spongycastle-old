package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.RC2ParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.sasn1.Asn1Integer;
import org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import org.bouncycastle.sasn1.BerOctetStringGenerator;
import org.bouncycastle.sasn1.BerSequenceGenerator;

/**
 * General class for generating a CMS enveloped-data message stream.
 * <p>
 * A simple example of usage.
 * <pre>
 *      CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
 *
 *      edGen.addKeyTransRecipient(cert);
 *
 *      ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
 *      
 *      OutputStream out = edGen.open(
 *                              bOut, CMSEnvelopedDataGenerator.AES128_CBC, "BC");*
 *      out.write(data);
 *      
 *      out.close();
 * </pre>
 */
public class CMSEnvelopedDataStreamGenerator
{
    public static final String  DES_EDE3_CBC    = "1.2.840.113549.3.7";
    public static final String  RC2_CBC         = "1.2.840.113549.3.2";
    public static final String  IDEA_CBC        = "1.3.6.1.4.1.188.7.1.1.2";
    public static final String  CAST5_CBC       = "1.2.840.113533.7.66.10";
    public static final String  AES128_CBC      = NISTObjectIdentifiers.id_aes128_CBC.getId(); 
    public static final String  AES192_CBC      = NISTObjectIdentifiers.id_aes192_CBC.getId(); 
    public static final String  AES256_CBC      = NISTObjectIdentifiers.id_aes256_CBC.getId(); 

    SecureRandom  rand = new SecureRandom();

    ArrayList                   recipientInfs = new ArrayList();
    private Object              _originatorInfo = null;
    private Object              _unprotectedAttributes = null;
    private int                 _bufferSize;
    
    private class RecipientInf
    {
        X509Certificate         cert;
        AlgorithmIdentifier     keyEncAlg;
        PublicKey               pubKey;
        ASN1OctetString         subKeyId;

        SecretKey               secKey;
        KEKIdentifier           secKeyId;

        RecipientInf(
            X509Certificate cert)
        {
            this.cert = cert;
            this.pubKey = cert.getPublicKey();

            try
            {
                byte[]                  bytes = cert.getTBSCertificate();
                ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
                ASN1InputStream         aIn = new ASN1InputStream(bIn);

                TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(aIn.readObject());
                SubjectPublicKeyInfo    info = tbs.getSubjectPublicKeyInfo();

                keyEncAlg = info.getAlgorithmId();
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("can't extract key algorithm from this cert");
            }
            catch (CertificateEncodingException e)
            {
                throw new IllegalArgumentException("can't extract tbs structure from this cert");
            }
        }

        RecipientInf(
            PublicKey               pubKey,
            ASN1OctetString         subKeyId)
        {
            this.pubKey = pubKey;
            this.subKeyId = subKeyId; 

            try
            {
                byte[]                  bytes = pubKey.getEncoded();
                ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
                ASN1InputStream         aIn = new ASN1InputStream(bIn);

                SubjectPublicKeyInfo    info = SubjectPublicKeyInfo.getInstance(aIn.readObject());

                keyEncAlg = info.getAlgorithmId();
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("can't extract key algorithm from this key");
            }
        }

        RecipientInf(
            SecretKey               secKey,
            KEKIdentifier           secKeyId)
        {
            this.secKey = secKey;
            this.secKeyId = secKeyId;

            if (secKey.getAlgorithm().startsWith("DES"))
            {
                keyEncAlg = new AlgorithmIdentifier(
                        new DERObjectIdentifier("1.2.840.113549.1.9.16.3.6"),
                            new DERNull());
            }
            else if (secKey.getAlgorithm().startsWith("RC2"))
            {
                keyEncAlg = new AlgorithmIdentifier(
                        new DERObjectIdentifier("1.2.840.113549.1.9.16.3.7"),
                        new DERInteger(58));
            }
            else if (secKey.getAlgorithm().startsWith("AES"))
            {
                int length = secKey.getEncoded().length * 8;
                DERObjectIdentifier wrapOid = null;
                
                if (length == 128)
                {
                    wrapOid = NISTObjectIdentifiers.id_aes128_wrap;
                }
                else if (length == 192)
                {
                    wrapOid = NISTObjectIdentifiers.id_aes192_wrap;
                }
                else if (length == 256)
                {
                    wrapOid = NISTObjectIdentifiers.id_aes256_wrap;
                }
                else
                {
                    throw new IllegalArgumentException("illegal keysize in AES");
                }
                
                keyEncAlg = new AlgorithmIdentifier(wrapOid, new DERNull());
            }
            else
            {
                throw new IllegalArgumentException("unknown algorithm");
            }
        }

        RecipientInfo toRecipientInfo(
            SecretKey           key,
            String              prov)
            throws IOException, GeneralSecurityException
        {
            Cipher                  keyCipher = Cipher.getInstance(
                                         keyEncAlg.getObjectId().getId(), prov);

            if (pubKey != null)
            {
                byte[]              rawKey = key.getEncoded();

                keyCipher.init(Cipher.ENCRYPT_MODE, pubKey);

                ASN1OctetString         encKey = new DEROctetString(
                                            keyCipher.doFinal(rawKey));

                if (cert != null)
                {
                    ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getTBSCertificate());
                    ASN1InputStream         aIn = new ASN1InputStream(bIn);
                    TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(aIn.readObject());
                    IssuerAndSerialNumber   encSid = new IssuerAndSerialNumber(tbs.getIssuer(), tbs.getSerialNumber().getValue());


                    return new RecipientInfo(new KeyTransRecipientInfo(
                            new RecipientIdentifier(encSid),
                            keyEncAlg,
                            encKey));
                }
                else
                {
                    return new RecipientInfo(new KeyTransRecipientInfo(
                            new RecipientIdentifier(subKeyId),
                            keyEncAlg,
                            encKey));
                }
            }
            else
            {
                keyCipher.init(Cipher.WRAP_MODE, secKey);

                ASN1OctetString         encKey = new DEROctetString(
                                                        keyCipher.wrap(key));

                return new RecipientInfo(new KEKRecipientInfo(
                                                secKeyId, keyEncAlg, encKey));
            }
        }
    }

    /**
     * base constructor
     */
    public CMSEnvelopedDataStreamGenerator()
    {
    }


    /**
     * Set the underlying string size for encapsulated data
     * 
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
        int bufferSize)
    {
        _bufferSize = bufferSize;
    }
    
    /**
     * add a recipient.
     */
    public void addKeyTransRecipient(
        X509Certificate cert)
        throws IllegalArgumentException
    {
        recipientInfs.add(new RecipientInf(cert));
    }

    /**
     * add a recipient
     *
     * @param key the public key used by the recipient
     * @param subKeyId the identifier for the recipient's public key
     */
    public void addKeyTransRecipient(
        PublicKey   key,
        byte[]      subKeyId)
        throws IllegalArgumentException
    {
        recipientInfs.add(new RecipientInf(key, new DEROctetString(subKeyId)));
    }

    /**
     * add a KEK recipient.
     */
    public void addKEKRecipient(
        SecretKey   key,
        byte[]      keyIdentifier)
        throws IllegalArgumentException
    {
        recipientInfs.add(new RecipientInf(key, new KEKIdentifier(
                                                keyIdentifier, null, null)));
    }
    
    private Asn1Integer getVersion()
    {
        if (_originatorInfo != null || _unprotectedAttributes != null)
        {
            return new Asn1Integer(2);
        }
        else
        {
            return new Asn1Integer(0);
        }
    }
    
    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider and the passed in key generator.
     * @throws IOException 
     */
    private OutputStream open(
        OutputStream out,
        String       encryptionOID,
        KeyGenerator keyGen,
        String       provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        try
        {
            //
            // ContentInfo
            //
            BerSequenceGenerator cGen = new BerSequenceGenerator(out);
            
            cGen.addObject(new Asn1ObjectIdentifier(CMSObjectIdentifiers.envelopedData.getId()));
            
            //
            // Signed Data
            //
            BerSequenceGenerator envGen = new BerSequenceGenerator(cGen.getRawOutputStream(), 0, true);
            
            envGen.addObject(getVersion());
    
            AlgorithmIdentifier     encAlgId;
            SecretKey               encKey;

            Cipher              cipher = Cipher.getInstance(encryptionOID, provider);
            AlgorithmParameters params;
            DEREncodable        asn1Params;
            
            encKey = keyGen.generateKey();

            Iterator            it = recipientInfs.iterator();
            ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
            
            while (it.hasNext())
            {
                RecipientInf            recipient = (RecipientInf)it.next();

                try
                {
                    recipientInfos.add(recipient.toRecipientInfo(encKey, provider));
                }
                catch (IOException e)
                {
                    throw new CMSException("encoding error.", e);
                }
                catch (InvalidKeyException e)
                {
                    throw new CMSException("key inappropriate for algorithm.", e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new CMSException("error making encrypted content.", e);
                }
            }
            
            envGen.getRawOutputStream().write(new DERSet(recipientInfos).getEncoded());
            
            try
            {
                AlgorithmParameterGenerator pGen = AlgorithmParameterGenerator.getInstance(encryptionOID, provider);

                if (encryptionOID.equals(RC2_CBC))
                {
                    byte[]  iv = new byte[8];

                    //
                    // mix in a bit extra...
                    //
                    rand.setSeed(System.currentTimeMillis());

                    rand.nextBytes(iv);

                    pGen.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, iv));
                }
                
                params = pGen.generateParameters();

                ByteArrayInputStream        bIn = new ByteArrayInputStream(params.getEncoded("ASN.1"));
                ASN1InputStream             aIn = new ASN1InputStream(bIn);

                asn1Params = aIn.readObject();
            }
            catch (NoSuchAlgorithmException e)
            {
                params = null;
                asn1Params = new DERNull();
            }

            encAlgId = new AlgorithmIdentifier(
                                new DERObjectIdentifier(encryptionOID),
                                asn1Params);

            cipher.init(Cipher.ENCRYPT_MODE, encKey, params);

            BerSequenceGenerator eiGen = new BerSequenceGenerator(envGen.getRawOutputStream());
            
            eiGen.addObject(new Asn1ObjectIdentifier(PKCSObjectIdentifiers.data.getId()));
            
            eiGen.getRawOutputStream().write(encAlgId.getEncoded());
            
            BerOctetStringGenerator octGen = new BerOctetStringGenerator(eiGen.getRawOutputStream(), 0, true);
            
            CipherOutputStream      cOut;
            
            if (_bufferSize != 0)
            {
                cOut = new CipherOutputStream(octGen.getOctetOutputStream(new byte[_bufferSize]), cipher);
            }
            else
            {
                cOut = new CipherOutputStream(octGen.getOctetOutputStream(), cipher);
            }

            return new CmsEnvelopedDataOutputStream(cOut, cGen, envGen, eiGen);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new CMSException("algorithm parameters invalid.", e);
        }
        catch (IOException e)
        {
            throw new CMSException("exception decoding algorithm parameters.", e);
        }
    }
    
    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     * @throws IOException 
     */
    public OutputStream open(
        OutputStream    out,
        String          encryptionOID,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException
    {
        try
        {
            KeyGenerator                keyGen = KeyGenerator.getInstance(
                                                    encryptionOID, provider);
                                                    
            return open(out, encryptionOID, keyGen, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find key generation algorithm.", e);
        }
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     * @throws IOException 
     */
    public OutputStream open(
        OutputStream    out,
        String          encryptionOID,
        int             keySize,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException
    {
        try
        {
            KeyGenerator                keyGen = KeyGenerator.getInstance(
                                                    encryptionOID, provider);
            
            keyGen.init(keySize);

            return open(out, encryptionOID, keyGen, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find key generation algorithm.", e);
        }
    }
    
    private class CmsEnvelopedDataOutputStream
        extends OutputStream
    {
        private CipherOutputStream   _out;
        private BerSequenceGenerator _cGen;
        private BerSequenceGenerator _envGen;
        private BerSequenceGenerator _eiGen;
    
        public CmsEnvelopedDataOutputStream(
            CipherOutputStream   out,
            BerSequenceGenerator cGen, 
            BerSequenceGenerator envGen,
            BerSequenceGenerator eiGen)
        {
            _out = out;
            _cGen = cGen;
            _envGen = envGen;
            _eiGen = eiGen;
        }
    
        public void write(
            int b)
            throws IOException
        {
            _out.write(b);
        }
        
        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            _out.write(bytes, off, len);
        }
        
        public void write(
            byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }
        
        public void close()
            throws IOException
        {
            _out.close();
            _eiGen.close();
            
            // [TODO] unprotected attributes go here
    
            _envGen.close();
            _cGen.close();
        }
    }
}
