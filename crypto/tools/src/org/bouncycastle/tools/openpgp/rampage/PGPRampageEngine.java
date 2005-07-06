package org.bouncycastle.tools.openpgp.rampage;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyValidationException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.tools.openpgp.util.PGPParams;
import org.bouncycastle.tools.openpgp.util.ProcessingEngine;



/**
 * A general tool for manipulating PGP objects.
 */
public class PGPRampageEngine implements ProcessingEngine
{
    private boolean   _verbose = true;
    private PGPParams _params  = null;

    public PGPRampageEngine(PGPParams params)
    {
        _params = params;
    }


    // Do the job!

    public void process()
    {
        boolean error = false;
        if (_params == null)
        {
            System.out.println("null parameters, much bad");
            return;
        }

        try
        {
            if (_params.isDecrypting())
            {
                if (((_params.getSecretKeyRingFile() != null) || (_params.getPassPhrase() != null))
                        && (_params.getPublicKeyRingFile() != null))
                {
                    FileInputStream inFile = new FileInputStream(_params.getInputFile());
                    char[] pass = _params.getKeyPassPhrase().toCharArray();

                    if (_params.getKeyPassPhrase() != null)
                    {
                        FileInputStream publicRing = new FileInputStream(_params.getPublicKeyRingFile());
                        FileInputStream secretRing = new FileInputStream(_params.getSecretKeyRingFile());
                        decryptKeyBasedFile(inFile, publicRing, secretRing, pass, _params.isMDCRequired());
                    }
                    else
                    {
                        decryptPBEBasedFile(inFile, pass, _params.isMDCRequired());
                    }

                    // Blank out passphrase in memory - no longer needed
                    blank(pass);
                }
                else
                {
                    System.out.println("Decryption could not be completed due to lack of information");
                    error = true;
                }
            }
            else if (_params.isEncrypting())
            {
                if ((_params.getPublicKeyRingFile() != null) && (_params.getRecipient() != null))
                {
                    File inFile = _params.getInputFile();
                    String inputFileName = inFile.getAbsolutePath();
                    String fileSuffix = _params.isAsciiArmor()? PGPParams.ASCII_SUFFIX:
                                                                PGPParams.BINARY_SUFFIX;
                    String outputFileName = _params.getOutputFilename();
                    if (outputFileName == null) {
                        outputFileName = inputFileName + fileSuffix;
                    }
                    FileInputStream publicRing = new FileInputStream(_params.getPublicKeyRingFile());

                    encryptFile(outputFileName, inFile, publicRing, _params.getRecipient(),
                                _params.isAsciiArmor(), _params.isMDCRequired());
                }
                else
                {
                    System.out.println("Encryption could not be completed due to lack of information");
                    error = true;
                }
            }
            else if (_params.isVerify())
            {
                if (_params.getPublicKeyRingFile() != null)
                {
                    FileInputStream inFile = new FileInputStream(_params.getInputFile());
                    FileInputStream publicRing = new FileInputStream(_params.getPublicKeyRingFile());

                    verifyFile(inFile, publicRing);
                }
                else
                {
                    System.out.println("Public keyring is required for signature verification");
                    error = true;
                }
            }
            else if (_params.isSigning())
            {
                if ((_params.getPublicKeyRingFile() != null) && (_params.getSecretKeyRingFile() != null) &&
                    (_params.getKeyPassPhrase() != null))
                {
                    File inFile = _params.getInputFile();
                    String inputFileName = inFile.getAbsolutePath();
                    String fileSuffix = _params.isAsciiArmor()? PGPParams.ASCII_SUFFIX:
                                                                PGPParams.BINARY_SUFFIX;
                    String outputFileName = _params.getOutputFilename();
                    if (outputFileName == null) {
                        outputFileName = inputFileName + fileSuffix;
                    }
                    FileInputStream publicRing = new FileInputStream(_params.getPublicKeyRingFile());
                    FileInputStream secretRing = new FileInputStream(_params.getSecretKeyRingFile());
                    char[] pass = _params.getKeyPassPhrase().toCharArray();

                    signFile(outputFileName, inFile, publicRing, secretRing, _params.getSignor(), pass,
                             _params.isAsciiArmor());

                    // Blank out passphrase in memory - no longer needed
                    blank(pass);
                }
                else
                {
                    System.out.println("Both keyrings and passphrase are required for signing");
                    error = true;
                }
            }
            else
            {
                System.out.println("Operation not implemented - please wait");
                error = true;
            }

        }

        catch (PGPException e)
        {
            Exception ue = e.getUnderlyingException();
            if (ue != null) {
                System.err.println(e.toString() + ": " + ue.toString());
            } else {
                System.err.println(e.toString());
            }
            error = true;
        }
        catch (Exception e)
        {
            System.err.println(e.toString());
            error = true;
        }

        if (error)
        {
            // System.out.println("error!");
            System.exit(1);
        }
    }



    /**
     * Find the public key for the recipient
     */
    private PGPPublicKey readPublicKey(InputStream in, String recipient, boolean encrypting)
        throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        PGPPublicKey key = null;

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();

        //System.out.println("processing public key ring, looking for : "+recipient);
        while (key == null && rIt.hasNext())
        {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            //System.out.println("Found a ring with keys ");
            Iterator kIt = kRing.getPublicKeys();

            while (key == null && kIt.hasNext())
            {
                PGPPublicKey k = (PGPPublicKey) kIt.next();
                Iterator userIDs = k.getUserIDs();
                String name = "<not specified>";
                if (userIDs.hasNext())
                {
                    name = (String) userIDs.next();
                }
                //System.out.println("found a key with name "+name);

                if (name.indexOf(recipient) >= 0)
                {
                    if (!encrypting || k.isEncryptionKey())
                    {
                        //System.out.println("Found the key I'm looking for");
                        key = k;
                    }
                }
            }
        }

        if (key == null)
        {
            throw new PGPException("Can't find encryption key in key ring");
        }

        return key;
    }



    /**
     * Load a public key ring collection from keyIn and find the key corresponding to
     * keyID if it exists.
     *
     * @param keyIn      input stream representing a key ring collection.
     * @param keyID      keyID we want.
     * @param encrypting whether we are encrypting or not
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    private static PGPPublicKey findPublicKey(InputStream keyIn, long keyID, boolean encrypting)
        throws IOException, PGPException, NoSuchProviderException
    {
        PGPPublicKeyRingCollection pubRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn));

        PGPPublicKey    pubKey = pubRing.getPublicKey(keyID);

        if (pubKey != null)
        {
            if (encrypting && !pubKey.isEncryptionKey())
            {
                throw new PGPException("Key is not an encryption key");
            }
        }
        else
        {
            throw new PGPException("Can't find public key in key ring");
        }

        return pubKey;
    }



    /**
     * Load a secret key ring collection from keyIn and find the secret key corresponding to
     * keyID if it exists.
     *
     * @param keyIn input stream representing a key ring collection.
     * @param keyID keyID we want.
     * @param pass passphrase to decrypt secret key with.
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    private static PGPSecretKey findSecretKey(InputStream keyIn, long keyID, boolean signing)
        throws IOException, PGPException, NoSuchProviderException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));

        PGPSecretKey    pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey != null)
        {
            if (signing && !pgpSecKey.isSigningKey())
            {
                throw new PGPException("Key is not a signing key");
            }
        }
        else
        {
            throw new PGPException("Can't find secret key in key ring");
        }

        return pgpSecKey;
    }



    /**
     * A simple routine that opens a key ring file and finds the first available
     * key suitable for signature generation.
     * 
     * @param in
     * @return
     * @throws IOException
     * @throws PGPException
     */
    private static PGPSecretKey findSigningKey(InputStream keyIn)
        throws IOException, PGPException
    {
        PGPSecretKeyRingCollection    pgpSec = new PGPSecretKeyRingCollection(
                                                            PGPUtil.getDecoderStream(keyIn));

        //
        // We just loop through the collection till we find a key suitable for encryption.
        //
        PGPSecretKey    key = null;

        Iterator rIt = pgpSec.getKeyRings();

        while (key == null && rIt.hasNext())
        {
            PGPSecretKeyRing kRing = (PGPSecretKeyRing) rIt.next();    
            Iterator         kIt = kRing.getSecretKeys();

            while (key == null && kIt.hasNext())
            {
                PGPSecretKey k = (PGPSecretKey) kIt.next();
                if (k.isSigningKey())
                {
                    key = k;
                }
            }
        }
        
        if (key == null)
        {
            throw new PGPException("Can't find a signing key in the key ring");
        }
        
        return key;
    }



    /**
     * Zero out the passed in character array
     */
    private static void blank(char[] bytes)
    {
        for (int t = 0; t < bytes.length; t++)
        {
            bytes[t]=0;
        }
    }



    /**
     * encrypt a file
     */
    private void encryptFile(String outputFilename, File inFile, InputStream publicRing,
                             String recipient, boolean armor, boolean withIntegrityCheck)
        throws PGPException
    {
        try
        {
            PGPPublicKey encKey = readPublicKey(publicRing, recipient, true);

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                    PGPCompressedData.ZIP);

            PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, inFile);

            comData.close();

            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                    PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(), "BC");

            cPk.addMethod(encKey);

            byte[] bytes = bOut.toByteArray();

            OutputStream out = new FileOutputStream(outputFilename);
            OutputStream aOut;

            if (armor)
            {
                aOut = new ArmoredOutputStream(out);
            }
            else
            {
                aOut = out;
            }

            OutputStream cOut = cPk.open(aOut, bytes.length);

            cOut.write(bytes);

            cPk.close();

            if (armor)
            {
                aOut.close();
            }
            out.close();
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Error in encryption", e);
        }
    }



    /**
     * decrypt the passed in message stream
     */
    public void decryptKeyBasedFile(InputStream fileToDecrypt,
                                       InputStream publicKeyInputStream,
                                       InputStream secretKeyInputStream,
                                       char[] passwd, boolean mdcRequired)
        throws PGPException
    {
    	try {
            fileToDecrypt = PGPUtil.getDecoderStream(fileToDecrypt);

            PGPObjectFactory outerWrapper = new PGPObjectFactory(fileToDecrypt);
            PGPEncryptedDataList enc;

            Object o = outerWrapper.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList) o;
            }
            else
            {
                enc = (PGPEncryptedDataList) outerWrapper.nextObject();
            }

            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(secretKeyInputStream));

            PGPSecretKey pgpSecKey = null;
            PGPPublicKeyEncryptedData pked = null;
            int count = 0;

            // find the secret key that is needed
            while (count != enc.size())
            {
                if (enc.get(count) instanceof PGPPublicKeyEncryptedData)
                {
                    pked = (PGPPublicKeyEncryptedData) enc.get(count);
                    pgpSecKey = pgpSec.getSecretKey(pked.getKeyID());
                    if (pgpSecKey != null)
                    {
                        break;
                    }
                }

                count++;
            }

            if (pgpSecKey == null)
            {
                throw new PGPException("Corresponding secret key not found");
            }

            InputStream clear = pked.getDataStream(pgpSecKey.extractPrivateKey(passwd, "BC"), "BC");

            PGPObjectFactory plainFact = new PGPObjectFactory(clear);

            PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();

            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());

            Object message = pgpFact.nextObject();

            // Blank out password in memory - no longer needed
            blank(passwd);

            // Plain file
            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData) message;

                FileOutputStream fOut = new FileOutputStream(ld.getFileName());

                InputStream unc = ld.getInputStream();

                int ch;
                while ((ch = unc.read()) >= 0)
                {
                    fOut.write(ch);
                }
            }
            else if (message instanceof PGPOnePassSignatureList)
            // One-pass signature
            {
                PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(publicKeyInputStream));

                PGPOnePassSignatureList onePassSigList = (PGPOnePassSignatureList) message;
                PGPOnePassSignature onePassSig = null;
                PGPPublicKey key = null;

                count = 0;
                while (count < onePassSigList.size())
                {
                    onePassSig = onePassSigList.get(count);
                    key = pgpRing.getPublicKey(onePassSig.getKeyID());
                    if (key != null)
                    {
                        break;
                    }

                    count++;
                }

                if (key == null)
                {
                    throw new PGPException("Corresponding public key not found");
                }

                PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

                InputStream dataIn = ld.getInputStream();

                FileOutputStream out = new FileOutputStream(ld.getFileName());

                PGPPublicKey publicKey = pgpRing.getPublicKey(onePassSig.getKeyID());

                onePassSig.initVerify(publicKey, "BC");

                int ch;
                while ((ch = dataIn.read()) >= 0)
                {
                    onePassSig.update((byte) ch);
                    out.write(ch);
                }
                out.close();

                PGPSignatureList sigList = (PGPSignatureList) pgpFact.nextObject();
                if (!onePassSig.verify(sigList.get(0)))
                {
                    // System.out.println("Signature verification failed");
                    throw new PGPException("Signature verification failed");
                }

                System.out.println("Signature verified");
            }
            else if (message instanceof PGPSignatureList)
            // Signature list
            {
                PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(publicKeyInputStream));

                PGPSignatureList sigList = (PGPSignatureList) message;
                PGPSignature sig = null;
                PGPPublicKey key = null;

                count = 0;
                while (count < sigList.size())
                {
                    sig = sigList.get(count);
                    key = pgpRing.getPublicKey(sig.getKeyID());
                    if (key != null)
                    {
                        break;
                    }

                    count++;
                }

                if (key == null)
                {
                    throw new PGPException("Corresponding public key not found");
                }

                PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

                InputStream dataIn = ld.getInputStream();

                FileOutputStream out = new FileOutputStream(ld.getFileName());

                sig.initVerify(key, "BC");

                int ch;
                while ((ch = dataIn.read()) >= 0)
                {
                    sig.update((byte) ch);
                    out.write(ch);
                }
                out.close();

                if (!sig.verify())
                {
                    // System.out.println("Signature verification failed");
                    throw new PGPException("Signature verification failed");
                }

                System.out.println("Signature verified");
            }
            else
            // what?
            {
                // System.out.println("Unrecognised message type");
                throw new PGPException("Unrecognised PGP message type");
            }

            if (pked.isIntegrityProtected())
            {
                if (!pked.verify())
                {
                    if (_verbose)
                    {
                        System.out.println("message failed integrity check");
                    }
                    throw new PGPException("Message failed integrity check");
                }

                if (_verbose)
                {
                    System.out.println("Message integrity check passed");
                }
            }
            else
            {
                if (_verbose)
                {
                    System.out.println("No message integrity check");
                }

                if (mdcRequired)
                {
                    throw new PGPException("Missing required message integrity check");
                }
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Error in decryption", e);
        }
    }



    /**
     * decrypt the passed in message stream
     */
    public void decryptPBEBasedFile(InputStream in, char[] passPhrase, boolean mdcRequired)
        throws PGPException
    {
        try {
            //
            // we need to be able to reset the stream if we try a
            // wrong password, we'll assume that all the mechanisms
            // appear in the first 10k for the moment...
            //
            int READ_LIMIT = 10 * 1024;

            in.mark(READ_LIMIT);

            PGPPBEEncryptedData pbe;
            InputStream clear;
            int count = 0;

            for (;;)
            {
                InputStream dIn = PGPUtil.getDecoderStream(in);

                PGPObjectFactory pgpF = new PGPObjectFactory(dIn);
                PGPEncryptedDataList enc;
                Object o = pgpF.nextObject();

                //
                // the first object might be a PGP marker packet.
                //
                if (o instanceof PGPEncryptedDataList)
                {
                    enc = (PGPEncryptedDataList) o;
                }
                else
                {
                    enc = (PGPEncryptedDataList) pgpF.nextObject();
                }

                while (count < enc.size())
                {
                    if (enc.get(count) instanceof PGPPBEEncryptedData)
                    {
                        break;
                    }

                    count++;
                }

                if (count >= enc.size())
                {
                    throw new PGPException("Password invalid");
                }

                pbe = (PGPPBEEncryptedData) enc.get(count);

                try
                {
                    clear = pbe.getDataStream(passPhrase, "BC");
                }
                catch (PGPKeyValidationException e)
                {
                    in.reset();
                    continue;
                }

                break;
            }

            PGPObjectFactory pgpFact = new PGPObjectFactory(clear);

            PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

            pgpFact = new PGPObjectFactory(cData.getDataStream());

            PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

            FileOutputStream fOut = new FileOutputStream(ld.getFileName());

            InputStream unc = ld.getInputStream();

            int ch;
            while ((ch = unc.read()) >= 0)
            {
                fOut.write(ch);
            }

            if (pbe.isIntegrityProtected())
            {
                if (!pbe.verify())
                {
                    if (_verbose)
                    {
                        System.out.println("Message failed integrity check");
                    }
                    throw new PGPException("Message failed integrity check");
                }
                if (_verbose)
                {
                    System.out.println("Message integrity check passed");
                }
            }
            else
            {
                if (_verbose)
                {
                    System.out.println("No message integrity check");
                }

                if (mdcRequired)
                {
                    throw new PGPException("Missing required message integrity check");
                }
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Error in decryption", e);
        }
    }


    /**
     * verify the passed in file as being correctly signed.
     */
    public void verifyFile(InputStream in, InputStream keyIn)
        throws PGPException
    {
        try {
            in = PGPUtil.getDecoderStream(in);

            //
            // a clear signed file
            //
            if (in instanceof ArmoredInputStream && ((ArmoredInputStream) in).isClearText())
            {
                //
                // read the input, making sure we ingore the last newline.
                //
                ArmoredInputStream aIn = (ArmoredInputStream) in;
                boolean newLine = false;
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                int ch;
                while ((ch = aIn.read()) >= 0 && aIn.isClearText())
                {
                    if (newLine)
                    {
                        bOut.write((byte) '\n');
                        newLine = false;
                    }
                    if (ch == '\n')
                    {
                        newLine = true;
                        continue;
                    }

                    bOut.write((byte) ch);
                }

                PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(keyIn);

                PGPObjectFactory pgpFact = new PGPObjectFactory(aIn);
                PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
                PGPSignature sig = null;
                PGPPublicKey key = null;

                int count = 0;
                while (count < p3.size())
                {
                    sig = (PGPSignature) p3.get(count);
                    key = pgpRings.getPublicKey(sig.getKeyID());
                    if (key != null)
                    {
                        break;
                    }

                    count++;
                }

                if (key == null)
                {
                    throw new PGPException("Corresponding public key not found");
                }

                sig.initVerify(key, "BC");

                sig.update(bOut.toByteArray());

                if (!sig.verify())
                {
                    if (_verbose)
                    {
                        System.out.println("Signature verification failed.");
                    }
                    throw new PGPException("Signature verification failed.");
                }
                if (_verbose)
                {
                    System.out.println("Signature verified.");
                }
            }
            else
            {
                PGPObjectFactory pgpFact = new PGPObjectFactory(in);

                PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

                pgpFact = new PGPObjectFactory(c1.getDataStream());

                Object message = pgpFact.nextObject();

                PGPPublicKey key = null;

                if (message instanceof PGPOnePassSignatureList)
                // One-pass signature list
                {
                    PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn));

                    PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
                    PGPOnePassSignature ops = null;

                    int count = 0;
                    while (count < p1.size())
                    {
                        ops = p1.get(count);
                        key = pgpRing.getPublicKey(ops.getKeyID());
                        if (key != null)
                        {
                            break;
                        }

                        count++;
                    }

                    if (key == null)
                    {
                        throw new PGPException("Corresponding public key not found");
                    }

                    PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
                    InputStream dIn = p2.getInputStream();
                    FileOutputStream out = new FileOutputStream(p2.getFileName());

                    ops.initVerify(key, "BC");

                    int ch;
                    while ((ch = dIn.read()) >= 0)
                    {
                        ops.update((byte) ch);
                        out.write(ch);
                    }

                    out.close();

                    PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

                    if (!ops.verify(p3.get(0)))
                    {
                        if (_verbose)
                        {
                            System.out.println("Signature verification failed.");
                        }
                        throw new PGPException("Signature verification failed.");
                    }
                }
                else if (message instanceof PGPSignatureList)
                // Signature list
                {
                    PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn));

                    PGPSignatureList sigList = (PGPSignatureList) message;
                    PGPSignature sig = null;

                    int count = 0;
                    while (count < sigList.size())
                    {
                        sig = sigList.get(count);
                        key = pgpRing.getPublicKey(sig.getKeyID());
                        if (key != null)
                        {
                            break;
                        }

                        count++;
                    }

                    if (key == null)
                    {
                        throw new PGPException("Corresponding public key not found");
                    }

                    PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

                    InputStream dataIn = ld.getInputStream();

                    FileOutputStream out = new FileOutputStream(ld.getFileName());

                    sig.initVerify(key, "BC");

                    int ch;
                    while ((ch = dataIn.read()) >= 0)
                    {
                        sig.update((byte) ch);
                        out.write(ch);
                    }
                    out.close();

                    if (!sig.verify())
                    {
                        if (_verbose)
                        {
                            System.out.println("Signature verification failed.");
                        }
                        throw new PGPException("Signature verification failed.");
                    }
                }
                else
                // what?
                {
                    // System.out.println("Unrecognised message type");
                    throw new PGPException("Unrecognised PGP message type");
                }
            }
            if (_verbose)
            {
                System.out.println("Signature verified.");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Error in verification", e);
        }
    }



    /**
     * Sign the passed in message stream
     */
    public void signFile(String outputFilename, File inFile,
                         InputStream publicRing,
                         InputStream secretRing,
                         String signor, char[] passwd, boolean armor)
        throws PGPException
    {
        try {
            PGPPublicKey publicKey;
            PGPSecretKey secretKey;

            if (signor != null) {
                publicKey = readPublicKey(publicRing, signor, false);
                secretKey = findSecretKey(secretRing, publicKey.getKeyID(), true);
            } else {
                // Just look for the first signing key on the secret keyring (if any)
            	secretKey = findSigningKey(secretRing);
            	publicKey = findPublicKey(publicRing, secretKey.getKeyID(), false);
            }

            PGPPrivateKey privateKey = secretKey.extractPrivateKey(passwd, "BC");
            PGPSignatureGenerator sGen = new PGPSignatureGenerator(publicKey.getAlgorithm(), PGPUtil.SHA1, "BC");

            sGen.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);

            Iterator users = publicKey.getUserIDs();
            if (users.hasNext())
            {
                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

                spGen.setSignerUserID(false, (String) users.next());
                sGen.setHashedSubpackets(spGen.generate());
            }

            PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

            OutputStream out = new FileOutputStream(outputFilename);
            OutputStream aOut;

            if (armor)
            {
                aOut = new ArmoredOutputStream(out);
            }
            else
            {
                aOut = out;
            }

            BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(aOut));

            sGen.generateOnePassVersion(false).encode(bOut);

            PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
            OutputStream            lOut = lGen.open(bOut, PGPLiteralData.BINARY, inFile);
            FileInputStream         fIn = new FileInputStream(inFile);

            int ch;
            while ((ch = fIn.read()) >= 0)
            {
                lOut.write(ch);
                sGen.update((byte)ch);
            }

            // close() finishes the writing of the literal data and flushes the stream
            // It does not close bOut so this is ok here
            lGen.close();

            sGen.generate().encode(bOut);

            bOut.finish();
            bOut.flush();

            cGen.close();

            if (armor)
            {
                // close() just finishes and flushes the stream but does not close it
                aOut.close();
            }
            out.close();
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Error in signing", e);
        }
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
