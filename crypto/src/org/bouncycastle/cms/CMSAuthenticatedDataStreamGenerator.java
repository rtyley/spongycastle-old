package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Iterator;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.GenericKey;

/**
 * General class for generating a CMS authenticated-data message stream.
 * <p>
 * A simple example of usage.
 * <pre>
 *      CMSAuthenticatedDataStreamGenerator edGen = new CMSAuthenticatedDataStreamGenerator();
 *
 *      edGen.addKeyTransRecipient(cert);
 *
 *      ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
 *
 *      OutputStream out = edGen.open(
 *                              bOut, CMSAuthenticatedDataGenerator.AES128_CBC, "BC");*
 *      out.write(data);
 *
 *      out.close();
 * </pre>
 */
public class CMSAuthenticatedDataStreamGenerator
    extends CMSAuthenticatedGenerator
{
    // Currently not handled
//    private Object              _originatorInfo = null;
//    private Object              _unprotectedAttributes = null;
    private int                 _bufferSize;
    private boolean             _berEncodeRecipientSet;

    /**
     * base constructor
     */
    public CMSAuthenticatedDataStreamGenerator()
    {
    }

    /**
     * constructor allowing specific source of randomness
     * @param rand instance of SecureRandom to use
     */
    public CMSAuthenticatedDataStreamGenerator(
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
     * Use a BER Set to store the recipient information
     */
    public void setBEREncodeRecipients(
        boolean berEncodeRecipientSet)
    {
        _berEncodeRecipientSet = berEncodeRecipientSet;
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider and the passed in key generator.
     * @throws java.io.IOException
     */
    private OutputStream open(
        OutputStream out,
        String       macOID,
        KeyGenerator keyGen,
        Provider     provider)
        throws NoSuchAlgorithmException, CMSException
    {
        Provider            encProvider = keyGen.getProvider();
        SecretKey           encKey = keyGen.generateKey();
        AlgorithmParameterSpec params = generateParameterSpec(macOID, encKey, encProvider);

        Iterator it = oldRecipientInfoGenerators.iterator();
        ASN1EncodableVector recipientInfos = new ASN1EncodableVector();

        while (it.hasNext())
        {
            IntRecipientInfoGenerator recipient = (IntRecipientInfoGenerator)it.next();

            try
            {
                recipientInfos.add(recipient.generate(encKey, rand, provider));
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

        for (it = recipientInfoGenerators.iterator(); it.hasNext();)
        {
            RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

            recipientInfos.add(recipient.generate(new GenericKey(encKey)));
        }

        return open(out, macOID, encKey, params, recipientInfos, encProvider);
    }

    protected OutputStream open(
        OutputStream        out,
        String              macOID,
        SecretKey           encKey,
        AlgorithmParameterSpec params,
        ASN1EncodableVector recipientInfos,
        String              provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return open(out, macOID, encKey, params, recipientInfos, CMSUtils.getProvider(provider));
    }

    protected OutputStream open(
        OutputStream        out,
        String              macOID,
        SecretKey           encKey,
        AlgorithmParameterSpec params,
        ASN1EncodableVector recipientInfos,
        Provider            provider)
        throws NoSuchAlgorithmException, CMSException
    {
        try
        {
            //
            // ContentInfo
            //
            BERSequenceGenerator cGen = new BERSequenceGenerator(out);

            cGen.addObject(CMSObjectIdentifiers.authenticatedData);

            //
            // Authenticated Data
            //
            BERSequenceGenerator authGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);

            authGen.addObject(new DERInteger(AuthenticatedData.calculateVersion(null)));

            if (_berEncodeRecipientSet)
            {
                authGen.getRawOutputStream().write(new BERSet(recipientInfos).getEncoded());
            }
            else
            {
                authGen.getRawOutputStream().write(new DERSet(recipientInfos).getEncoded());
            }

            Mac mac = CMSEnvelopedHelper.INSTANCE.getMac(macOID, provider);

            mac.init(encKey, params);

            AlgorithmIdentifier macAlgId = getAlgorithmIdentifier(macOID, params, provider);

            authGen.getRawOutputStream().write(macAlgId.getEncoded());
            
            BERSequenceGenerator eiGen = new BERSequenceGenerator(authGen.getRawOutputStream());

            eiGen.addObject(CMSObjectIdentifiers.data);

            OutputStream octetStream = CMSUtils.createBEROctetOutputStream(
                    eiGen.getRawOutputStream(), 0, false, _bufferSize);

            MacOutputStream mOut = new MacOutputStream(octetStream, mac);

            return new CmsAuthenticatedDataOutputStream(mOut, cGen, authGen, eiGen);
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
            throw new CMSException("algorithm parameter invalid.", e);
        }
        catch (InvalidParameterSpecException e)
        {
            throw new CMSException("algorithm parameter spec invalid.", e);
        }
        catch (IOException e)
        {
            throw new CMSException("exception decoding algorithm parameters.", e);
        }
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     * @throws java.io.IOException
     */
    public OutputStream open(
        OutputStream    out,
        String          encryptionOID,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException
    {
        return open(out, encryptionOID, CMSUtils.getProvider(provider));
    }

    public OutputStream open(
        OutputStream    out,
        String          encryptionOID,
        Provider        provider)
        throws NoSuchAlgorithmException, CMSException, IOException
    {
        KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createSymmetricKeyGenerator(encryptionOID, provider);

        keyGen.init(rand);

        return open(out, encryptionOID, keyGen, provider);
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     */
    public OutputStream open(
        OutputStream    out,
        String          encryptionOID,
        int             keySize,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException
    {
        return open(out, encryptionOID, keySize, CMSUtils.getProvider(provider));
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     */
    public OutputStream open(
        OutputStream    out,
        String          encryptionOID,
        int             keySize,
        Provider        provider)
        throws NoSuchAlgorithmException, CMSException, IOException
    {
        KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createSymmetricKeyGenerator(encryptionOID, provider);

        keyGen.init(keySize, rand);

        return open(out, encryptionOID, keyGen, provider);
    }

    private class CmsAuthenticatedDataOutputStream
        extends OutputStream
    {
        private MacOutputStream macStream;
        private BERSequenceGenerator cGen;
        private BERSequenceGenerator envGen;
        private BERSequenceGenerator eiGen;

        public CmsAuthenticatedDataOutputStream(
            MacOutputStream macStream,
            BERSequenceGenerator cGen,
            BERSequenceGenerator envGen,
            BERSequenceGenerator eiGen)
        {
            this.macStream = macStream;
            this.cGen = cGen;
            this.envGen = envGen;
            this.eiGen = eiGen;
        }

        public void write(
            int b)
            throws IOException
        {
            macStream.write(b);
        }

        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            macStream.write(bytes, off, len);
        }

        public void write(
            byte[] bytes)
            throws IOException
        {
            macStream.write(bytes);
        }

        public void close()
            throws IOException
        {
            macStream.close();
            eiGen.close();

            // [TODO] auth attributes go here           
            envGen.addObject(new DEROctetString(macStream.getMac()));
            // [TODO] unauth attributes go here

            envGen.close();
            cGen.close();
        }
    }
}