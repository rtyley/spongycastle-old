package org.bouncycastle.tools.openpgp.dump;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.tools.openpgp.util.PGPParams;
import org.bouncycastle.tools.openpgp.util.ProcessingEngine;

/**
 * 
 */
public class PGPDumpEngine implements ProcessingEngine
{
    private PGPParams                  _params = null;
    private PGPSecretKeyRingCollection _pgpSecRingCache;
    private PGPPublicKeyRingCollection _pgpPubRingCache;

    public PGPDumpEngine(PGPParams params)
    {
        _params = params;
    }

    public void process()
    {
        InputStream rawFile;
        try
        {
            rawFile = new FileInputStream(_params.getInputFile());
            InputStream openPGPMessage = PGPUtil.getDecoderStream(rawFile);

            PGPObjectFactory pgpFact = new PGPObjectFactory(openPGPMessage);

            Object nextObject = pgpFact.nextObject();
            while (nextObject != null)
            {
                if (nextObject instanceof PGPEncryptedDataList)
                {
                    System.out.println("Found an encrypted OpenPGP message...\n");
                    processEncryptedDataList((PGPEncryptedDataList) nextObject);
                }
                else if (nextObject instanceof PGPCompressedData)
                {
                    System.out.println("Found unencrypted compressed data...\n");
                    processUnencryptedData((PGPCompressedData) nextObject);
                }
                else
                {
                    System.out.println("Found an object called: " + nextObject.getClass() + "\n");
                }
                nextObject = pgpFact.nextObject();
            }
        }
        catch (Exception unexpected)
        {
            unexpected.printStackTrace();
        }
    }

    private void processEncryptedDataList(PGPEncryptedDataList edl) throws Exception
    {

        PGPPublicKeyEncryptedData pked = findValidPublicKeyEncryptedData(edl);

        if (pked == null)
        {
            System.out.println("Corresponding secret key not found, cannot process remainder");
            return;
        }

        PGPSecretKey pgpSecKey = _pgpSecRingCache.getSecretKey(pked.getKeyID());

        char[] passPhrase = _params.getKeyPassPhrase().toCharArray();
        InputStream decryptedDataList = null;
        PGPObjectFactory plainFact = null;
        PGPCompressedData cData = null;
        PGPObjectFactory plainObjectFactory = null;
        Object message = null;

        decryptedDataList = pked.getDataStream(pgpSecKey.extractPrivateKey(passPhrase, BouncyCastleProvider.PROVIDER_NAME), BouncyCastleProvider.PROVIDER_NAME);
        plainFact = new PGPObjectFactory(decryptedDataList);

        message = plainFact.nextObject();
        if (message instanceof PGPCompressedData)
        {
            cData = (PGPCompressedData) message;
        }
        else
        {
            System.out.println("Can only process compressed data. "
                    + " Please report this message to feedback-crypto@bouncycastle.org");
            return;
        }

        plainObjectFactory = new PGPObjectFactory(cData.getDataStream());

        message = plainObjectFactory.nextObject();

        while (message != null)
        {
            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData) message;
                // ld should be a PGPInputStreamPacket when the marker interface is implemented                
                readAndDiscardInputStreamPacket(ld);
                System.out.println("Found the data for the file: " + ld.getFileName() + "\n");
            }
            else if (message instanceof PGPOnePassSignatureList)
            {
                PGPOnePassSignatureList onePassSigList = (PGPOnePassSignatureList) message;
                processOnePassSignatureList(onePassSigList);
            }
            else if (message instanceof PGPSignatureList)
            {
                PGPSignatureList sigList = (PGPSignatureList) message;
                processSignatureList(sigList);
            }
            else
            {
                System.out.println("Found an *unexpected* object called: "
                        + message.getClass());
            }
            message = plainObjectFactory.nextObject();
        }

    }

    private void processUnencryptedData(PGPCompressedData cData) throws Exception
    {
        PGPObjectFactory plainObjectFactory = null;
        Object message = null;

        plainObjectFactory = new PGPObjectFactory(cData.getDataStream());

        message = plainObjectFactory.nextObject();

        while (message != null)
        {
            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData) message;
                // ld should be a PGPInputStreamPacket when the marker interface is implemented                
                readAndDiscardInputStreamPacket(ld);
                System.out.println("Found the data for the file: " + ld.getFileName() + "\n");
            }
            else if (message instanceof PGPOnePassSignatureList)
            {
                PGPOnePassSignatureList onePassSigList = (PGPOnePassSignatureList) message;
                processOnePassSignatureList(onePassSigList);
            }
            else if (message instanceof PGPSignatureList)
            {
                PGPSignatureList sigList = (PGPSignatureList) message;
                processSignatureList(sigList);
            }
            else
            {
                System.out.println("Found an *unexpected* object called: "
                        + message.getClass());
            }
            message = plainObjectFactory.nextObject();
        }

    }

    private void processSignatureList(PGPSignatureList sigList)
    {
        for (int i = 0; i < sigList.size(); i++)
        {
            Object obj = sigList.get(i);
            if (obj instanceof PGPSignature)
            {
                PGPSignature sig = (PGPSignature) obj;
                System.out.println(pgpSigDump(sig));
            }
            else
            {
                System.out.println("Found an *unexpected* object called: " + obj.getClass());
            }
        }
    }

    private String pgpSigDump(PGPSignature sig)
    {
        if (sig == null)
        {
            return "Found null Signature";
        }

        StringBuffer sb = new StringBuffer("Found Signature: ");
        sb.append(asHex(sig.getKeyID()));
        sb.append('\n');

        sb.append("Creation: ").append(sig.getCreationTime()).append('\n');

        PGPPublicKey pubKey = findPublicKey(sig.getKeyID());

        if (pubKey != null) {
            userDataDump(sb, pubKey);
        } else {
            sb.append("Cannot find associated public key\n");
        }

        return sb.toString();
    }

    // TODO: ld should be a PGPInputStreamPacket
    private void readAndDiscardInputStreamPacket(PGPLiteralData ld)
    {
        InputStream is = ld.getInputStream();
        try
        {
            int ch;
            while ((ch = is.read()) >= 0)
            {
                // do nothing;
            }
        }
        catch (IOException unexpected)
        {
            unexpected.printStackTrace();
        }
    }

    private void processOnePassSignatureList(PGPOnePassSignatureList sigList)
    {
        if (sigList == null)
        {
            return;
        }

        System.out.println("-- start 1PS list");
        for (int i = 0; i < sigList.size(); i++)
        {
            PGPOnePassSignature sig = (PGPOnePassSignature) sigList.get(i);
            if (i > 0) {
                System.out.print("\n");
            }
            System.out.print(pgpOnePassSigDump(sig));
        }

        System.out.println("-- end 1PS list\n");
    }

    private String pgpOnePassSigDump(PGPOnePassSignature sig)
    {
        if (sig == null)
        {
            return "Found null One-Pass Signature\n";
        }

        StringBuffer sb = new StringBuffer("Found One-Pass Signature: ");
        sb.append(asHex(sig.getKeyID()));
        sb.append('\n');

        // sb.append("Creation: ").append(sig.getCreationTime()).append("\n");

        PGPPublicKey pubKey = findPublicKey(sig.getKeyID());

        if (pubKey != null) {
            userDataDump(sb, pubKey);
        } else {
            sb.append("Cannot find associated public key\n");
        }

        return sb.toString();
    }

    private PGPPublicKeyEncryptedData findValidPublicKeyEncryptedData(PGPEncryptedDataList edl)
    {
        PGPSecretKey pgpSecKey = null;

        int count = 0;

        PGPPublicKeyEncryptedData pked = null;
        while (count != edl.size())
        {
            Object obj = edl.get(count);
            if (obj instanceof PGPPublicKeyEncryptedData)
            {
                System.out.print("Found some PGPPublicKeyEncryptedData, ");
                pked = (PGPPublicKeyEncryptedData) obj;
                long keyId = pked.getKeyID();
                System.out.println("Encrypted by " + asHex(keyId));
                
                pgpSecKey = findSecretKey(keyId);

                if (pgpSecKey != null)
                {
                    // TODO: Produce more information here about the key, such as user id
                    System.out.println("Found matching key " + asHex(pgpSecKey.getKeyID())
                            + ": ");
                    System.out.println(secKeyDump(pgpSecKey));
                    break;
                }
                else
                {
                    System.out.println("");
                }
            }
            else
            {
                System.out.println("Found an object in the PGPEncryptedDataList of: "
                        + obj.getClass());
            }

            count++;
        }
        return pked;
    }

    private String secKeyDump(PGPSecretKey pgpSecKey)
    {
        if (pgpSecKey == null)
        {
            return "Key is null";
        }

        StringBuffer sb = new StringBuffer("SecretKey: ");
        sb.append(asHex(pgpSecKey.getKeyID()));
        sb.append('\n');

        PGPPublicKey pubKey = findPublicKey(pgpSecKey.getKeyID());
        // need to grab the public key information or something
        // for data about the "master key"

        if (pubKey != null) {
            userDataDump(sb, pubKey);
        } else {
            sb.append("Cannot find associated public key\n");
        }

        return sb.toString();
    }

    private String pubKeyDump(PGPPublicKey pubKey)
    {
        if (pubKey == null)
        {
            return "Key is null";
        }

        StringBuffer sb = new StringBuffer("PublicKey: ");
        sb.append(asHex(pubKey.getKeyID()));
        sb.append('\n');

        userDataDump(sb, pubKey);

        return sb.toString();
    }

    private void userDataDump(StringBuffer sb, PGPPublicKey pubKey)
    {
        Iterator i = pubKey.getUserIDs();
        sb.append("Id list: ");
        if ((i != null) && i.hasNext())
        {
            while (i.hasNext())
            {
                String id = (String) i.next();
                sb.append('\"').append(id).append("\" ");
            }
        }
        else
        {
            sb.append("<none>");
        }
        sb.append('\n');

        /*
        i = pubKey.getUserAttributes();
        sb.append("Attribute list: ");
        if ((i != null) && i.hasNext())
        {
            while (i.hasNext())
            {
                String id = (String) i.next();
                sb.append("\"").append(id).append("\" ");
            }
        }
        else
        {
            sb.append("<none>");
        }
        */
    }

    private PGPPublicKey findPublicKey(long keyID)
    {
        if (_pgpPubRingCache == null && _params.getPublicKeyRingFile() != null)
        {
            try
            {
                _pgpPubRingCache = new PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(new FileInputStream(
                                _params.getPublicKeyRingFile())));
            }
            catch (Exception unexpected)
            {
                System.out.println("Error occurred processing the public key ring:");
                unexpected.printStackTrace();
            }
        }
        
        PGPPublicKey key = null; 
        
        if (_pgpPubRingCache != null)
        {
            try
            {
                key = _pgpPubRingCache.getPublicKey(keyID);
            }
            catch (PGPException unexpected)
            {
                unexpected.printStackTrace();
            }
        }
        
        return key;
    }

    private PGPSecretKey findSecretKey(long keyID)
    {
        PGPSecretKeyRingCollection keyRing = null;
        if (_pgpSecRingCache == null && _params.getSecretKeyRingFile() != null)
        {
            try
            {
                _pgpSecRingCache = new PGPSecretKeyRingCollection(
                        PGPUtil.getDecoderStream(new FileInputStream(
                                _params.getSecretKeyRingFile())));
            }
            catch (Exception unexpected)
            {
                System.out.println("Error occurred processing the secret key ring:");
                unexpected.printStackTrace();
            }
        }
        
        PGPSecretKey key = null; 
        
        if (_pgpSecRingCache != null)
        {
            try
            {
                key = _pgpSecRingCache.getSecretKey(keyID);
            }
            catch (PGPException unexpected)
            {
                unexpected.printStackTrace();
            }
        }
        
        return key;
    }

    private String asHex(long l)
    {
        return Long.toHexString(l).substring(8);
    }
    
    // TODO: Implement these methods so that can be used by the CmdLineProcessors
    // and the test cases.
    public boolean isError()
    {
        return false;
    }

    public Collection errorMessages()
    {
        return null;
    }    
}
