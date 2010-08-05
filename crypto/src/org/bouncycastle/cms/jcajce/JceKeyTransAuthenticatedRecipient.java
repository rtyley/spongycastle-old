package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Mac;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.operator.MacCalculator;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret
 * key encrypted using their public key that needs to be used to
 * extract the message.
 */
public class JceKeyTransAuthenticatedRecipient
    extends JceKeyTransRecipient
{
    public JceKeyTransAuthenticatedRecipient(PrivateKey recipientKey)
    {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentMacAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, encryptedContentEncryptionKey);

        final Mac dataMac = helper.createContentMac(secretKey, contentMacAlgorithm);

        return new RecipientOperator(new MacCalculator()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentMacAlgorithm;
            }

            public OutputStream getOutputStream()
            {
                return new MacOutputStream(dataMac);
            }

            public byte[] getMac()
            {
                return dataMac.doFinal();
            }
        });
    }

    private class MacOutputStream
        extends OutputStream
    {
        protected Mac mac;

        public MacOutputStream(
            Mac          mac)
        {
            this.mac = mac;
        }

        public void write(int b)
            throws IOException
        {
            mac.update((byte)b);
        }

        public void write(
            byte[] b,
            int off,
            int len)
            throws IOException
        {
            mac.update(b, off, len);
        }

        public Mac getMac()
        {
            return mac;
        }
    }
}
