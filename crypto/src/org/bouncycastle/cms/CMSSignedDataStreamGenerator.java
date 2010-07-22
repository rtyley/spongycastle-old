package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.ContentDigester;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.io.TeeOutputStream;

/**
 * General class for generating a pkcs7-signature message stream.
 * <p>
 * A simple example of usage.
 * </p>
 * <pre>
 *      CertStore                    certs...
 *      CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
 *  
 *      gen.addSigner(privateKey, cert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "BC");
 *  
 *      gen.addCertificatesAndCRLs(certs);
 *  
 *      OutputStream sigOut = gen.open(bOut);
 *  
 *      sigOut.write("Hello World!".getBytes());
 *      
 *      sigOut.close();
 * </pre>
 */
public class CMSSignedDataStreamGenerator
    extends CMSSignedGenerator
{
    private List _signerInfs = new ArrayList();
    private List _messageDigests = new ArrayList();
    private int  _bufferSize;

    private class DigestAndSignerInfoGeneratorHolder
    {
        SignerIntInfoGenerator signerInf;
        MessageDigest       digest;
        String              digestOID;

        DigestAndSignerInfoGeneratorHolder(SignerIntInfoGenerator signerInf, MessageDigest digest, String digestOID)
        {
            this.signerInf = signerInf;
            this.digest = digest;
            this.digestOID = digestOID;
        }

        AlgorithmIdentifier getDigestAlgorithm()
        {
            return new AlgorithmIdentifier(new DERObjectIdentifier(digestOID), DERNull.INSTANCE);
        }
    }

    private class SignerIntInfoGeneratorImpl
        implements SignerIntInfoGenerator
    {
        private final SignerIdentifier            _signerIdentifier;
        private final String                      _encOID;
        private final CMSAttributeTableGenerator  _sAttr;
        private final CMSAttributeTableGenerator  _unsAttr;
        private final String                      _encName;
        private final Signature                   _sig;

        SignerIntInfoGeneratorImpl(
            PrivateKey                  key,
            SignerIdentifier            signerIdentifier,
            String                      digestOID,
            String                      encOID,
            CMSAttributeTableGenerator  sAttr,
            CMSAttributeTableGenerator  unsAttr,
            Provider                    sigProvider,
            SecureRandom                random)
            throws NoSuchAlgorithmException, InvalidKeyException
        {
            _signerIdentifier = signerIdentifier;
            _encOID = encOID;
            _sAttr = sAttr;
            _unsAttr = unsAttr;
            _encName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(_encOID);

            String digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
            String signatureName = digestName + "with" + _encName;

            if (_sAttr != null)
            {
                _sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, sigProvider);
            }
            else
            {
                // Note: Need to use raw signatures here since we have already calculated the digest
                if (_encName.equals("RSA"))
                {
                    _sig = CMSSignedHelper.INSTANCE.getSignatureInstance("RSA", sigProvider);
                }
                else if (_encName.equals("DSA"))
                {
                    _sig = CMSSignedHelper.INSTANCE.getSignatureInstance("NONEwithDSA", sigProvider);
                }
                // TODO Add support for raw PSS
//                else if (_encName("RSAandMGF1"))
//                {
//                    sig = CMSSignedHelper.INSTANCE.getSignatureInstance("NONEWITHRSAPSS", _sigProvider);
//                    try
//                    {
//                        // Init the params this way to avoid having a 'raw' version of each PSS algorithm
//                        Signature sig2 = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, _sigProvider);
//                        PSSParameterSpec spec = (PSSParameterSpec)sig2.getParameters().getParameterSpec(PSSParameterSpec.class);
//                        sig.setParameter(spec);
//                    }
//                    catch (Exception e)
//                    {
//                        throw new SignatureException("algorithm: " + _encName + " could not be configured.");
//                    }
//                }
                else
                {
                    throw new NoSuchAlgorithmException("algorithm: " + _encName + " not supported in base signatures.");
                }
            }

            _sig.initSign(key, random);
        }

        public SignerInfo generate(DERObjectIdentifier contentType, AlgorithmIdentifier digestAlgorithm,
            byte[] calculatedDigest) throws CMSStreamException
        {
            try
            {
                byte[] bytesToSign = calculatedDigest;

                /* RFC 3852 5.4
                 * The result of the message digest calculation process depends on
                 * whether the signedAttrs field is present.  When the field is absent,
                 * the result is just the message digest of the content as described
                 * 
                 * above.  When the field is present, however, the result is the message
                 * digest of the complete DER encoding of the SignedAttrs value
                 * contained in the signedAttrs field.
                 */
                ASN1Set signedAttr = null;
                if (_sAttr != null)
                {
                    Map parameters = getBaseParameters(contentType, digestAlgorithm, calculatedDigest);
                    AttributeTable signed = _sAttr.getAttributes(Collections.unmodifiableMap(parameters));
    
                    // TODO Handle countersignatures (see CMSSignedDataGenerator)
    
                    signedAttr = getAttributeSet(signed);
    
                    // sig must be composed from the DER encoding.
                    bytesToSign = signedAttr.getEncoded(ASN1Encodable.DER);
                }
                else
                {
                    // Note: Need to use raw signatures here since we have already calculated the digest
                    if (_encName.equals("RSA"))
                    {
                        DigestInfo dInfo = new DigestInfo(digestAlgorithm, calculatedDigest);
                        bytesToSign = dInfo.getEncoded(ASN1Encodable.DER);
                    }
                }
    
                _sig.update(bytesToSign);
                byte[] sigBytes = _sig.sign();
     
                ASN1Set unsignedAttr = null;
                if (_unsAttr != null)
                {
                    Map parameters = getBaseParameters(contentType, digestAlgorithm, calculatedDigest);
                    parameters.put(CMSAttributeTableGenerator.SIGNATURE, sigBytes.clone());
    
                    AttributeTable unsigned = _unsAttr.getAttributes(Collections.unmodifiableMap(parameters));
    
                    unsignedAttr = getAttributeSet(unsigned);
                }
    
                AlgorithmIdentifier digestEncryptionAlgorithm = getEncAlgorithmIdentifier(_encOID, _sig);
    
                return new SignerInfo(_signerIdentifier, digestAlgorithm,
                    signedAttr, digestEncryptionAlgorithm, new DEROctetString(sigBytes), unsignedAttr);
            }
            catch (IOException e)
            {
                throw new CMSStreamException("encoding error.", e);
            }
            catch (SignatureException e)
            {
                throw new CMSStreamException("error creating signature.", e);
            }
        }
    }

    private class SignerInfoGeneratorImpl
        implements SignerInfoGenerator
    {
        private final SignerIdentifier            _signerIdentifier;
        private final String                      _encOID;
        private final CMSAttributeTableGenerator  _sAttr;
        private final CMSAttributeTableGenerator  _unsAttr;
        private final String                      _encName;
        private final Signature                   _sig;
        private final ContentSigner               signer;
        private final ContentDigester             digester;

        SignerInfoGeneratorImpl(
            PrivateKey                  key,
            SignerIdentifier            signerIdentifier,
            String                      digestOID,
            String                      encOID,
            CMSAttributeTableGenerator  sAttr,
            CMSAttributeTableGenerator  unsAttr,
            Provider                    sigProvider,
            SecureRandom                random)
            throws NoSuchAlgorithmException, InvalidKeyException
        {
            _signerIdentifier = signerIdentifier;
            _encOID = encOID;
            _sAttr = sAttr;
            _unsAttr = unsAttr;
            _encName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(_encOID);

            signer = null;
            digester = null;
            String digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
            String signatureName = digestName + "with" + _encName;

            if (_sAttr != null)
            {
                _sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, sigProvider);
            }
            else
            {
                // Note: Need to use raw signatures here since we have already calculated the digest
                if (_encName.equals("RSA"))
                {
                    _sig = CMSSignedHelper.INSTANCE.getSignatureInstance("RSA", sigProvider);
                }
                else if (_encName.equals("DSA"))
                {
                    _sig = CMSSignedHelper.INSTANCE.getSignatureInstance("NONEwithDSA", sigProvider);
                }
                // TODO Add support for raw PSS
//                else if (_encName("RSAandMGF1"))
//                {
//                    sig = CMSSignedHelper.INSTANCE.getSignatureInstance("NONEWITHRSAPSS", _sigProvider);
//                    try
//                    {
//                        // Init the params this way to avoid having a 'raw' version of each PSS algorithm
//                        Signature sig2 = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, _sigProvider);
//                        PSSParameterSpec spec = (PSSParameterSpec)sig2.getParameters().getParameterSpec(PSSParameterSpec.class);
//                        sig.setParameter(spec);
//                    }
//                    catch (Exception e)
//                    {
//                        throw new SignatureException("algorithm: " + _encName + " could not be configured.");
//                    }
//                }
                else
                {
                    throw new NoSuchAlgorithmException("algorithm: " + _encName + " not supported in base signatures.");
                }
            }

            _sig.initSign(key, random);
        }

        public OutputStream getCalculatingOutputStream()
        {
            if (_sAttr != null)
            {
                return digester.getOutputStream();
            }
            else
            {
                return signer.getOutputStream();
            }
        }

        public SignerInfo generate(ASN1ObjectIdentifier contentType)
            throws CMSStreamException
        {
            try
            {
                /* RFC 3852 5.4
                 * The result of the message digest calculation process depends on
                 * whether the signedAttrs field is present.  When the field is absent,
                 * the result is just the message digest of the content as described
                 *
                 * above.  When the field is present, however, the result is the message
                 * digest of the complete DER encoding of the SignedAttrs value
                 * contained in the signedAttrs field.
                 */
                ASN1Set signedAttr = null;
                byte[] calculatedDigest = null;

                if (_sAttr != null)
                {
                    calculatedDigest = digester.getDigest();
                    Map parameters = getBaseParameters(contentType, digester.getAlgorithmIdentifier(), calculatedDigest);
                    AttributeTable signed = _sAttr.getAttributes(Collections.unmodifiableMap(parameters));

                    // TODO Handle countersignatures (see CMSSignedDataGenerator)

                    signedAttr = getAttributeSet(signed);

                    // sig must be composed from the DER encoding.
                    OutputStream sOut = signer.getOutputStream();

                    sOut.write(signedAttr.getEncoded(ASN1Encodable.DER));

                    sOut.close();
                }

                byte[] sigBytes = signer.getSignature();

                ASN1Set unsignedAttr = null;
                if (_unsAttr != null)
                {
                    Map parameters = getBaseParameters(contentType, digester.getAlgorithmIdentifier(), calculatedDigest);
                    parameters.put(CMSAttributeTableGenerator.SIGNATURE, sigBytes.clone());

                    AttributeTable unsigned = _unsAttr.getAttributes(Collections.unmodifiableMap(parameters));

                    unsignedAttr = getAttributeSet(unsigned);
                }

                AlgorithmIdentifier digestEncryptionAlgorithm = getEncAlgorithmIdentifier(_encOID, _sig);

                return new SignerInfo(_signerIdentifier, digester.getAlgorithmIdentifier(),
                    signedAttr, digestEncryptionAlgorithm, new DEROctetString(sigBytes), unsignedAttr);
            }
            catch (IOException e)
            {
                throw new CMSStreamException("encoding error.", e);
            }
        }
    }

    /**
     * base constructor
     */
    public CMSSignedDataStreamGenerator()
    {
    }

    /**
     * constructor allowing specific source of randomness
     * @param rand instance of SecureRandom to use
     */
    public CMSSignedDataStreamGenerator(
        SecureRandom rand)
    {
        super(rand);
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
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, digestOID, CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, cert, digestOID, new DefaultSignedAttributeTableGenerator(),
           (CMSAttributeTableGenerator)null, sigProvider);
    }

    /**
     * add a signer, specifying the digest encryption algorithm - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID, CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer, specifying digest encryptionOID - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, cert, encryptionOID, digestOID, new DefaultSignedAttributeTableGenerator(),
           (CMSAttributeTableGenerator)null, sigProvider);
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, digestOID, signedAttr, unsignedAttr,
            CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, cert, digestOID, new DefaultSignedAttributeTableGenerator(signedAttr),
            new SimpleAttributeTableGenerator(unsignedAttr), sigProvider);
    }

    /**
     * add a signer with extra signed/unsigned attributes - specifying digest
     * encryption algorithm.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID, signedAttr, unsignedAttr,
            CMSUtils.getProvider(sigProvider));
    }

   /**
     * add a signer with extra signed/unsigned attributes and the digest encryption algorithm.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID,
            new DefaultSignedAttributeTableGenerator(signedAttr),
            new SimpleAttributeTableGenerator(unsignedAttr), sigProvider);
    }

    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, digestOID, signedAttrGenerator, unsignedAttrGenerator,
            CMSUtils.getProvider(sigProvider));
    }

    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, cert, getEncOID(key, digestOID), digestOID, signedAttrGenerator,
            unsignedAttrGenerator, sigProvider);
    }

    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, cert, encryptionOID, digestOID, signedAttrGenerator, unsignedAttrGenerator,
            CMSUtils.getProvider(sigProvider));
    }

    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        doAddSigner(key, getSignerIdentifier(cert), encryptionOID, digestOID, signedAttrGenerator,
            unsignedAttrGenerator, sigProvider, sigProvider);
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, digestOID, CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, subjectKeyID, digestOID, new DefaultSignedAttributeTableGenerator(),
           (CMSAttributeTableGenerator)null, sigProvider);
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          encryptionOID,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, encryptionOID, digestOID, CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here, specifying the digest encryption algorithm.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          encryptionOID,
        String          digestOID,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, subjectKeyID, encryptionOID, digestOID,
           new DefaultSignedAttributeTableGenerator(), (CMSAttributeTableGenerator)null,
           sigProvider);
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, digestOID, signedAttr, unsignedAttr,
            CMSUtils.getProvider(sigProvider));
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, digestOID,
            new DefaultSignedAttributeTableGenerator(signedAttr),
            new SimpleAttributeTableGenerator(unsignedAttr), sigProvider);
    }

    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, digestOID, signedAttrGenerator, unsignedAttrGenerator,
            CMSUtils.getProvider(sigProvider));
    }

    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, getEncOID(key, digestOID), digestOID, signedAttrGenerator,
            unsignedAttrGenerator, sigProvider);
    }

    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        addSigner(key, subjectKeyID, encryptionOID, digestOID, signedAttrGenerator,
            unsignedAttrGenerator, CMSUtils.getProvider(sigProvider));
    }

    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        doAddSigner(key, getSignerIdentifier(subjectKeyID), encryptionOID, digestOID,
            signedAttrGenerator, unsignedAttrGenerator, sigProvider, sigProvider);
    }

    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider,
        Provider                    digProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        doAddSigner(key, getSignerIdentifier(cert), encryptionOID, digestOID,
            signedAttrGenerator, unsignedAttrGenerator, sigProvider, digProvider);
    }

    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider,
        Provider                    digProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        doAddSigner(key, getSignerIdentifier(subjectKeyID), encryptionOID, digestOID,
            signedAttrGenerator, unsignedAttrGenerator, sigProvider, digProvider);
    }

    private void doAddSigner(
        PrivateKey                  key,
        SignerIdentifier            signerIdentifier,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        Provider                    sigProvider,
        Provider                    digProvider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        String          digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
        MessageDigest   dig = CMSSignedHelper.INSTANCE.getDigestInstance(digestName, digProvider);

        SignerIntInfoGeneratorImpl signerInf = new SignerIntInfoGeneratorImpl(key, signerIdentifier, digestOID, encryptionOID,
            signedAttrGenerator, unsignedAttrGenerator, sigProvider, rand);

        _signerInfs.add(new DigestAndSignerInfoGeneratorHolder(signerInf, dig, digestOID));
        _messageDigests.add(dig);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider.
     */
    public OutputStream open(
        OutputStream out)
        throws IOException
    {
        return open(out, false);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     */
    public OutputStream open(
        OutputStream out,
        boolean      encapsulate)
        throws IOException
    {
        return open(out, DATA, encapsulate);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data". If dataOutputStream is non null the data
     * being signed will be written to the stream as it is processed.
     * @param out stream the CMS object is to be written to.
     * @param encapsulate true if data should be encapsulated.
     * @param dataOutputStream output stream to copy the data being signed to.
     */
    public OutputStream open(
        OutputStream out,
        boolean      encapsulate,
        OutputStream dataOutputStream)
        throws IOException
    {
        return open(out, DATA, encapsulate, dataOutputStream);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     */
    public OutputStream open(
        OutputStream out,
        String       eContentType,
        boolean      encapsulate)
        throws IOException
    {
        return open(out, eContentType, encapsulate, null);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     * @param out stream the CMS object is to be written to.
     * @param eContentType OID for data to be signed.
     * @param encapsulate true if data should be encapsulated.
     * @param dataOutputStream output stream to copy the data being signed to.
     */
    public OutputStream open(
        OutputStream out,
        String       eContentType,
        boolean      encapsulate,
        OutputStream dataOutputStream)
        throws IOException
    {
        // TODO
//        if (_signerInfs.isEmpty())
//        {
//            /* RFC 3852 5.2
//             * "In the degenerate case where there are no signers, the
//             * EncapsulatedContentInfo value being "signed" is irrelevant.  In this
//             * case, the content type within the EncapsulatedContentInfo value being
//             * "signed" MUST be id-data (as defined in section 4), and the content
//             * field of the EncapsulatedContentInfo value MUST be omitted."
//             */
//            if (encapsulate)
//            {
//                throw new IllegalArgumentException("no signers, encapsulate must be false");
//            }
//            if (!DATA.equals(eContentType))
//            {
//                throw new IllegalArgumentException("no signers, eContentType must be id-data");
//            }
//        }
//
//        if (!DATA.equals(eContentType))
//        {
//            /* RFC 3852 5.3
//             * [The 'signedAttrs']...
//             * field is optional, but it MUST be present if the content type of
//             * the EncapsulatedContentInfo value being signed is not id-data.
//             */
//            // TODO signedAttrs must be present for all signers
//        }

        //
        // ContentInfo
        //
        BERSequenceGenerator sGen = new BERSequenceGenerator(out);
        
        sGen.addObject(CMSObjectIdentifiers.signedData);
        
        //
        // Signed Data
        //
        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        
        sigGen.addObject(calculateVersion(eContentType));
        
        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        
        //
        // add the precalculated SignerInfo digest algorithms.
        //
        for (Iterator it = _signers.iterator(); it.hasNext();)
        {
            SignerInformation signer = (SignerInformation)it.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));
        }
        
        //
        // add the new digests
        //
        for (Iterator it = _signerInfs.iterator(); it.hasNext();)
        {
            DigestAndSignerInfoGeneratorHolder holder = (DigestAndSignerInfoGeneratorHolder)it.next();
            digestAlgs.add(holder.getDigestAlgorithm());
        }
        
        sigGen.getRawOutputStream().write(new DERSet(digestAlgs).getEncoded());
        
        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());
        eiGen.addObject(new DERObjectIdentifier(eContentType));

        // If encapsulating, add the data as an octet string in the sequence
        OutputStream encapStream = encapsulate
            ? CMSUtils.createBEROctetOutputStream(eiGen.getRawOutputStream(), 0, true, _bufferSize)
            : null;

        // Also send the data to 'dataOutputStream' if necessary
        OutputStream contentStream = getSafeTeeOutputStream(dataOutputStream, encapStream);

        // Let all the digests see the data as it is written
        OutputStream digStream = attachDigestsToOutputStream(_messageDigests, contentStream);

        return new CmsSignedDataOutputStream(digStream, eContentType, sGen, sigGen, eiGen);
    }

    // TODO Make public?
    void generate(
        OutputStream    out,
        String          eContentType,
        boolean         encapsulate,
        OutputStream    dataOutputStream,
        CMSProcessable  content)
        throws CMSException, IOException
    {
        OutputStream signedOut = open(out, eContentType, encapsulate, dataOutputStream);
        if (content != null)
        {
            content.write(signedOut);
        }
        signedOut.close();
    }

    // RFC3852, section 5.1:
    // IF ((certificates is present) AND
    //    (any certificates with a type of other are present)) OR
    //    ((crls is present) AND
    //    (any crls with a type of other are present))
    // THEN version MUST be 5
    // ELSE
    //    IF (certificates is present) AND
    //       (any version 2 attribute certificates are present)
    //    THEN version MUST be 4
    //    ELSE
    //       IF ((certificates is present) AND
    //          (any version 1 attribute certificates are present)) OR
    //          (any SignerInfo structures are version 3) OR
    //          (encapContentInfo eContentType is other than id-data)
    //       THEN version MUST be 3
    //       ELSE version MUST be 1
    //
    private DERInteger calculateVersion(
        String contentOid)
    {
        boolean otherCert = false;
        boolean otherCrl = false;
        boolean attrCertV1Found = false;
        boolean attrCertV2Found = false;

        if (_certs != null)
        {
            for (Iterator it = _certs.iterator(); it.hasNext();)
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject)obj;

                    if (tagged.getTagNo() == 1)
                    {
                        attrCertV1Found = true;
                    }
                    else if (tagged.getTagNo() == 2)
                    {
                        attrCertV2Found = true;
                    }
                    else if (tagged.getTagNo() == 3)
                    {
                        otherCert = true;
                    }
                }
            }
        }

        if (otherCert)
        {
            return new DERInteger(5);
        }

        if (_crls != null && !otherCert)         // no need to check if otherCert is true
        {
            for (Iterator it = _crls.iterator(); it.hasNext();)
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    otherCrl = true;
                }
            }
        }

        if (otherCrl)
        {
            return new DERInteger(5);
        }

        if (attrCertV2Found)
        {
            return new DERInteger(4);
        }

        if (attrCertV1Found)
        {
            return new DERInteger(3);
        }

        if (contentOid.equals(DATA))
        {
            if (checkForVersion3(_signers))
            {
                return new DERInteger(3);
            }
            else
            {
                return new DERInteger(1);
            }
        }
        else
        {
            return new DERInteger(3);
        }
    }

    private boolean checkForVersion3(List signerInfos)
    {
        for (Iterator it = signerInfos.iterator(); it.hasNext();)
        {
            SignerInfo s = SignerInfo.getInstance(((SignerInformation)it.next()).toSignerInfo());

            if (s.getVersion().getValue().intValue() == 3)
            {
                return true;
            }
        }

        return false;
    }

    private static OutputStream attachDigestsToOutputStream(List digests, OutputStream s)
    {
        OutputStream result = s;
        Iterator it = digests.iterator();
        while (it.hasNext())
        {
            MessageDigest digest = (MessageDigest)it.next();
            result = getSafeTeeOutputStream(result, new DigOutputStream(digest));
        }
        return result;
    }

    private static OutputStream getSafeOutputStream(OutputStream s)
    {
        return s == null ? new NullOutputStream() : s;
    }

    private static OutputStream getSafeTeeOutputStream(OutputStream s1,
            OutputStream s2)
    {
        return s1 == null ? getSafeOutputStream(s2)
                : s2 == null ? getSafeOutputStream(s1) : new TeeOutputStream(
                        s1, s2);
    }

    private class CmsSignedDataOutputStream
        extends OutputStream
    {
        private OutputStream         _out;
        private DERObjectIdentifier  _contentOID;
        private BERSequenceGenerator _sGen;
        private BERSequenceGenerator _sigGen;
        private BERSequenceGenerator _eiGen;

        public CmsSignedDataOutputStream(
            OutputStream         out,
            String               contentOID,
            BERSequenceGenerator sGen,
            BERSequenceGenerator sigGen,
            BERSequenceGenerator eiGen)
        {
            _out = out;
            _contentOID = new DERObjectIdentifier(contentOID);
            _sGen = sGen;
            _sigGen = sigGen;
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

            _digests.clear();    // clear the current preserved digest state

            if (_certs.size() != 0)
            {
                ASN1Set certs = CMSUtils.createBerSetFromList(_certs);

                _sigGen.getRawOutputStream().write(new BERTaggedObject(false, 0, certs).getEncoded());
            }

            if (_crls.size() != 0)
            {
                ASN1Set crls = CMSUtils.createBerSetFromList(_crls);

                _sigGen.getRawOutputStream().write(new BERTaggedObject(false, 1, crls).getEncoded());
            }

            //
            // collect all the SignerInfo objects
            //
            ASN1EncodableVector signerInfos = new ASN1EncodableVector();

            //
            // add the generated SignerInfo objects
            //
            {
                Iterator it = _signerInfs.iterator();
                while (it.hasNext())
                {
                    DigestAndSignerInfoGeneratorHolder holder = (DigestAndSignerInfoGeneratorHolder)it.next();
    
                    byte[] calculatedDigest = holder.digest.digest();
                    _digests.put(holder.digestOID, calculatedDigest.clone());
                    AlgorithmIdentifier digestAlgorithm = holder.getDigestAlgorithm();
    
                    signerInfos.add(holder.signerInf.generate(_contentOID, digestAlgorithm, calculatedDigest));
                }
            }

            //
            // add the precalculated SignerInfo objects
            //
            {
                Iterator it = _signers.iterator();
                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();

                    // TODO Verify the content type and calculated digest match the precalculated SignerInfo
//                    if (!signer.getContentType().equals(_contentOID))
//                    {
//                        // TODO The precalculated content type did not match - error?
//                    }
//                    
//                    byte[] calculatedDigest = (byte[])_digests.get(signer.getDigestAlgOID());
//                    if (calculatedDigest == null)
//                    {
//                        // TODO We can't confirm this digest because we didn't calculate it - error?
//                    }
//                    else
//                    {
//                        if (!Arrays.areEqual(signer.getContentDigest(), calculatedDigest))
//                        {
//                            // TODO The precalculated digest did not match - error?
//                        }
//                    }

                    signerInfos.add(signer.toSignerInfo());
                }
            }
            
            _sigGen.getRawOutputStream().write(new DERSet(signerInfos).getEncoded());

            _sigGen.close();
            _sGen.close();
        }
    }
}
