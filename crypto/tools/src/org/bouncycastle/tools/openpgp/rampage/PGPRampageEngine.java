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
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import org.bouncycastle.openpgp.PGPV3SignatureGenerator;
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
            if (_params.isEncrypting() && _params.isSigning())
            {
                if ((_params.getPublicKeyRingFile() != null) && (_params.getSecretKeyRingFile() != null) &&
                    (_params.getRecipient() != null) && (_params.getKeyPassPhrase() != null))
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

                    encryptAndSignFile(outputFileName, inFile, publicRing, secretRing,
                                       _params.getRecipient(), _params.getSignor(), pass,
                                       _params.isAsciiArmor(), _params.isMDCRequired(),
                                       _params.isPGP2Compatible());

                    // Blank out passphrase in memory - no longer needed
                    blank(pass);

                    // Close the files
                    publicRing.close();
                    secretRing.close();
                }
                else
                {
                    System.out.println("Encrypt and sign could not be completed due to lack of information");
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
                                _params.isAsciiArmor(), _params.isMDCRequired(),
                                _params.isPGP2Compatible());

                    // Close the files
                    publicRing.close();
                }
                else
                {
                    System.out.println("Encryption could not be completed due to lack of information");
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
                             _params.isAsciiArmor(), _params.isPGP2Compatible());

                    // Blank out passphrase in memory - no longer needed
                    blank(pass);

                    // Close the files
                    publicRing.close();
                    secretRing.close();
                }
                else
                {
                    System.out.println("Both keyrings and passphrase are required for signing");
                    error = true;
                }
            }
            else if (_params.isDecrypting())
            {
                if (((_params.getSecretKeyRingFile() != null) || (_params.getPassPhrase() != null))
                        && (_params.getPublicKeyRingFile() != null))
                {
                    String outputFileName = _params.getOutputFilename();
                    FileInputStream inFile = new FileInputStream(_params.getInputFile());
                    char[] pass;

                    if (_params.getSecretKeyRingFile() != null)
                    {
                        FileInputStream publicRing = new FileInputStream(_params.getPublicKeyRingFile());
                        FileInputStream secretRing = new FileInputStream(_params.getSecretKeyRingFile());
                        pass = _params.getKeyPassPhrase().toCharArray();

                        decryptKeyBasedFile(outputFileName, inFile, publicRing, secretRing, pass,
                                            _params.isMDCRequired());

                        // Close the files
                        publicRing.close();
                        secretRing.close();
                    }
                    else
                    {
                        pass = _params.getPassPhrase().toCharArray();
                        decryptPBEBasedFile(outputFileName, inFile, pass, _params.isMDCRequired());
                    }

                    // Blank out passphrase in memory - no longer needed
                    blank(pass);

                    // Close the files
                    inFile.close();
                }
                else
                {
                    System.out.println("Decryption could not be completed due to lack of information");
                    error = true;
                }
            }
            else if (_params.isVerify())
            {
                if (_params.getPublicKeyRingFile() != null)
                {
                    String outputFileName = _params.getOutputFilename();
                    FileInputStream inFile = new FileInputStream(_params.getInputFile());
                    FileInputStream publicRing = new FileInputStream(_params.getPublicKeyRingFile());

                    verifyFile(outputFileName, inFile, publicRing);

                    // Close the files
                    publicRing.close();
                    inFile.close();
                }
                else
                {
                    System.out.println("Public keyring is required for signature verification");
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
                System.err.println("Error: " + e.getMessage() + " - " + ue.toString());
            } else {
                System.err.println("Error: " + e.getMessage());
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
     * Encrypt and sign the specified input file
     */
    public void encryptAndSignFile(String outputFilename, File inFile,
                                   InputStream publicRing, InputStream secretRing,
                                   String recipient, String signor, char[] passwd,
                                   boolean armor, boolean withIntegrityCheck,
                                   boolean oldFormat)
        throws PGPException
    {
        try
        {
            // Get the public keyring
            PGPPublicKeyRingCollection pubRing = new PGPPublicKeyRingCollection(
                                           PGPUtil.getDecoderStream(publicRing));

            // Get the secret keyring
            PGPSecretKeyRingCollection secRing = new PGPSecretKeyRingCollection(
                                           PGPUtil.getDecoderStream(secretRing));

            // Find the recipient's key
            PGPPublicKey encKey = readPublicKey(pubRing, recipient, true);
            if (encKey.isRevoked()) {
                String keyId = Long.toHexString(encKey.getKeyID()).substring(8);
                throw new PGPException("Encryption key (0x"+keyId+") has been revoked");
            }

            // Find the signing key
            PGPPublicKey publicKey;
            PGPSecretKey secretKey;
            if (signor != null) {
                publicKey = readPublicKey(pubRing, signor, false);
                secretKey = findSecretKey(secRing, publicKey.getKeyID(), true);
            } else {
                // Just look for the first signing key on the secret keyring (if any)
            	secretKey = findSigningKey(secRing);
            	publicKey = findPublicKey(pubRing, secretKey.getKeyID(), false);
            }
            if (publicKey.isRevoked()) {
                String keyId = Long.toHexString(publicKey.getKeyID()).substring(8);
                throw new PGPException("Signing key (0x"+keyId+") has been revoked");
            }

            PGPPrivateKey   privateKey = secretKey.extractPrivateKey(passwd, BouncyCastleProvider.PROVIDER_NAME);

            // Sign the data into an in-memory stream
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            if (oldFormat) {
                signDataV3(inFile, bOut, publicKey, privateKey);
            } else {
                signData(inFile, bOut, publicKey, privateKey);
            }

            // Now encrypt the result
            PGPEncryptedDataGenerator cPk = oldFormat?
               new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, new SecureRandom(), oldFormat, BouncyCastleProvider.PROVIDER_NAME):
               new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(), BouncyCastleProvider.PROVIDER_NAME);

            cPk.addMethod(encKey);

            byte[] bytes = bOut.toByteArray();

            OutputStream out  = new FileOutputStream(outputFilename);
            OutputStream aOut = armor? new ArmoredOutputStream(out): out;
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
     * Encrypt the specified input file
     */
    public void encryptFile(String outputFilename, File inFile, InputStream publicRing,
                            String recipient, boolean armor, boolean withIntegrityCheck,
                            boolean oldFormat)
        throws PGPException
    {
        try
        {
            // Get the public keyring
            PGPPublicKeyRingCollection pubRing = new PGPPublicKeyRingCollection(
                                          PGPUtil.getDecoderStream(publicRing));

            // Find the recipient's key
            PGPPublicKey encKey = readPublicKey(pubRing, recipient, true);
            if (encKey.isRevoked()) {
                String keyId = Long.toHexString(encKey.getKeyID()).substring(8);
                throw new PGPException("Encryption key (0x"+keyId+") has been revoked");
            }

            // Compress the data into an in-memory stream
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            compressData(inFile, bOut, oldFormat);

            // Now encrypt the result
            PGPEncryptedDataGenerator cPk = oldFormat?
               new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, new SecureRandom(), oldFormat, BouncyCastleProvider.PROVIDER_NAME):
               new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(), BouncyCastleProvider.PROVIDER_NAME);

            cPk.addMethod(encKey);

            byte[] bytes = bOut.toByteArray();

            OutputStream out  = new FileOutputStream(outputFilename);
            OutputStream aOut = armor? new ArmoredOutputStream(out): out;
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
     * Sign the specified file
     */
    public void signFile(String outputFilename, File inFile,
                         InputStream publicRing,
                         InputStream secretRing,
                         String signor, char[] passwd,
                         boolean armor, boolean oldFormat)
        throws PGPException
    {
        try {
            PGPPublicKey publicKey;
            PGPSecretKey secretKey;

            // Get the public keyring
            PGPPublicKeyRingCollection pubRing = new PGPPublicKeyRingCollection(
                                          PGPUtil.getDecoderStream(publicRing));

            // Get the secret keyring
            PGPSecretKeyRingCollection secRing = new PGPSecretKeyRingCollection(
                                           PGPUtil.getDecoderStream(secretRing));

            // Find the signing key
            if (signor != null) {
                publicKey = readPublicKey(pubRing, signor, false);
                secretKey = findSecretKey(secRing, publicKey.getKeyID(), true);
            } else {
                // Just look for the first signing key on the secret keyring (if any)
            	secretKey = findSigningKey(secRing);
            	publicKey = findPublicKey(pubRing, secretKey.getKeyID(), false);
            }
            if (publicKey.isRevoked()) {
                String keyId = Long.toHexString(publicKey.getKeyID()).substring(8);
                throw new PGPException("Signing key (0x"+keyId+") has been revoked");
            }

            PGPPrivateKey   privateKey = secretKey.extractPrivateKey(passwd, BouncyCastleProvider.PROVIDER_NAME);

            OutputStream out  = new FileOutputStream(outputFilename);
            OutputStream aOut = armor? new ArmoredOutputStream(out): out;

            // Sign the data
            if (oldFormat) {
                signDataV3(inFile, aOut, publicKey, privateKey);
            } else {
                signData(inFile, aOut, publicKey, privateKey);
            }

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


    /**
     * Sign the passed in message stream (version 3 signature)
     */
    private void signDataV3(File inFile, OutputStream aOut,
                            PGPPublicKey publicKey, PGPPrivateKey privateKey)
        throws PGPException
    {
        try {
            PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            BCPGOutputStream           bOut = new BCPGOutputStream(cGen.open(aOut));
            PGPLiteralDataGenerator    lGen = new PGPLiteralDataGenerator(true);

            PGPV3SignatureGenerator    s3Gen =
                    new PGPV3SignatureGenerator(publicKey.getAlgorithm(), PGPUtil.SHA1, BouncyCastleProvider.PROVIDER_NAME);

            s3Gen.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);

            s3Gen.generateOnePassVersion(false).encode(bOut);

            OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, inFile);

            FileInputStream fIn = new FileInputStream(inFile);

            int ch;
            while ((ch = fIn.read()) >= 0)
            {
                lOut.write(ch);
                s3Gen.update((byte)ch);
            }

            fIn.close();

            // close() finishes the writing of the literal data and flushes the stream
            // It does not close bOut so this is ok here
            lGen.close();

            // Generate the signature
            s3Gen.generate().encode(bOut);

            // Must not close bOut here
            bOut.finish();
            bOut.flush();

            cGen.close();
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

    /**
     * Sign the passed in message stream
     */
    private void signData(File inFile, OutputStream aOut,
                          PGPPublicKey publicKey, PGPPrivateKey privateKey)
        throws PGPException
    {
        try {
            PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            BCPGOutputStream           bOut = new BCPGOutputStream(cGen.open(aOut));
            PGPLiteralDataGenerator    lGen = new PGPLiteralDataGenerator();

            PGPSignatureGenerator sGen = 
                    new PGPSignatureGenerator(publicKey.getAlgorithm(), PGPUtil.SHA1, BouncyCastleProvider.PROVIDER_NAME);

            sGen.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);

            Iterator users = publicKey.getUserIDs();
            if (users.hasNext())
            {
                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                spGen.setSignerUserID(false, (String) users.next());
                sGen.setHashedSubpackets(spGen.generate());
            }

            sGen.generateOnePassVersion(false).encode(bOut);

            OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, inFile);

            FileInputStream fIn = new FileInputStream(inFile);

            int ch;
            while ((ch = fIn.read()) >= 0)
            {
                lOut.write(ch);
                sGen.update((byte)ch);
            }

            fIn.close();

            // close() finishes the writing of the literal data and flushes the stream
            // It does not close bOut so this is ok here
            lGen.close();

            // Generate the signature
            sGen.generate().encode(bOut);

            // Must not close bOut here
            bOut.finish();
            bOut.flush();

            cGen.close();
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


    /**
     * Compress the data in the input stream
     */
    private void compressData(File inFile, OutputStream bOut, boolean oldFormat)
        throws PGPException
    {
        try
        {
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

            PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator(oldFormat);
            OutputStream            pOut = lData.open(comData.open(bOut), PGPLiteralData.BINARY,
                                                      inFile.getName(), inFile.length(),
                                                      new Date(inFile.lastModified()));
            FileInputStream         fIn = new FileInputStream(inFile);
            byte[]                  bytes = new byte[4096];
            int                     len;

            while ((len = fIn.read(bytes)) > 0)
            {
                pOut.write(bytes, 0, len);
            }
        
            fIn.close();

            lData.close();
            comData.close();
        }
        catch (Exception e)
        {
            throw new PGPException("Error in encryption", e);
        }
    }



    /**
     * Decrypt the specified (PKE) input file
     */
    public void decryptKeyBasedFile(String outputFilename, InputStream inFile,
                                    InputStream publicRing, InputStream secretRing,
                                    char[] passwd, boolean mdcRequired)
        throws PGPException
    {
    	try {
            // Get the public keyring
            PGPPublicKeyRingCollection pubRing = new PGPPublicKeyRingCollection(
                                           PGPUtil.getDecoderStream(publicRing));

            InputStream fileToDecrypt = PGPUtil.getDecoderStream(inFile);

            PGPObjectFactory pgpFact = new PGPObjectFactory(fileToDecrypt);

            Object message = pgpFact.nextObject();

            PGPPublicKeyEncryptedData pked = null;
            PGPCompressedData cData;

            // Check for signed only
            if (!(message instanceof PGPCompressedData))
            {
                //
                // Encrypted - the first object might be a PGP marker packet.
                //
                if (!(message instanceof PGPEncryptedDataList))
                {
                    message = pgpFact.nextObject();
                    if (!(message instanceof PGPEncryptedDataList))
                    {
                        if (_verbose)
                        {
                            System.out.println("Unrecognised PGP message type");
                        }
                        throw new PGPException("Unrecognised PGP message type");
                    }
                }

                PGPEncryptedDataList enc = (PGPEncryptedDataList) message;

                PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(secretRing));

                PGPSecretKey pgpSecKey = null;
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

                // Check for revoked key
            	PGPPublicKey encKey = findPublicKey(pubRing, pgpSecKey.getKeyID(), true);
                if (encKey.isRevoked()) {
                    String keyId = Long.toHexString(encKey.getKeyID()).substring(8);
                    System.out.println("Warning: Encryption key (0x"+keyId+") has been revoked");
                    // throw new PGPException("Encryption key (0x"+keyId+") has been revoked");
                }

                InputStream clear = pked.getDataStream(pgpSecKey.extractPrivateKey(passwd, BouncyCastleProvider.PROVIDER_NAME), BouncyCastleProvider.PROVIDER_NAME);
   
                pgpFact = new PGPObjectFactory(clear);

                cData = (PGPCompressedData) pgpFact.nextObject();
            }
            else
            {
                cData = (PGPCompressedData) message;
            }

            // Blank out password in memory - no longer needed
            blank(passwd);

            pgpFact = new PGPObjectFactory(cData.getDataStream());

            message = pgpFact.nextObject();

            // Plain file
            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData) message;

                if (outputFilename == null)
                {
                    outputFilename = ld.getFileName();
                }

                FileOutputStream out = new FileOutputStream(outputFilename);

                InputStream dataIn = ld.getInputStream();

                int ch;
                while ((ch = dataIn.read()) >= 0)
                {
                    out.write(ch);
                }
                out.close();
            }
            else if (message instanceof PGPOnePassSignatureList)
            // One-pass signature
            {
                if (!checkOnePassSignature(outputFilename,
                                           (PGPOnePassSignatureList) message,
                                           pgpFact,
                                           pubRing))
                {
                    if (_verbose)
                    {
                        System.out.println("Signature verification failed");
                    }
                    throw new PGPException("Signature verification failed");
                }

                System.out.println("Signature verified");
            }
            else if (message instanceof PGPSignatureList)
            // Signature list
            {
                if (!checkSignature(outputFilename,
                                    (PGPSignatureList) message,
                                    pgpFact,
                                    pubRing))
                {
                    if (_verbose)
                    {
                        System.out.println("Signature verification failed");
                    }
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

            if (pked != null)
            {
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
     * Decrypt the specified (PBE) input file
     */
    public void decryptPBEBasedFile(String outputFilename, InputStream in,
                                    char[] passPhrase, boolean mdcRequired)
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
                    clear = pbe.getDataStream(passPhrase, BouncyCastleProvider.PROVIDER_NAME);
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

            if (outputFilename == null)
            {
                outputFilename = ld.getFileName();
            }

            FileOutputStream fOut = new FileOutputStream(outputFilename);

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
     * Verify the passed in file as being correctly signed.
     */
    public void verifyFile(String outputFilename, InputStream inFile, InputStream publicRing)
        throws PGPException
    {
        try {
            // Get the public keyring
            PGPPublicKeyRingCollection pubRing = new PGPPublicKeyRingCollection(
                                           PGPUtil.getDecoderStream(publicRing));

            InputStream in = PGPUtil.getDecoderStream(inFile);

            //
            // a clear signed file
            //
            if (in instanceof ArmoredInputStream && ((ArmoredInputStream) in).isClearText())
            {
                if (!checkClearsign(in, pubRing))
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

                if (message instanceof PGPOnePassSignatureList)
                // One-pass signature list
                {
                    if (!checkOnePassSignature(outputFilename,
                                               (PGPOnePassSignatureList) message,
                                               pgpFact,
                                               pubRing))
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
                    if (!checkSignature(outputFilename,
                                        (PGPSignatureList) message,
                                        pgpFact,
                                        pubRing))
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
                    if (_verbose)
                    {
                        System.out.println("Unrecognised PGP message type");
                    }
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
     * Check the signature in clear-signed data
     */
    private boolean checkClearsign(InputStream in, PGPPublicKeyRingCollection pgpRings)
        throws PGPException
    {
        try {
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
            if (key.isRevoked()) {
                String keyId = Long.toHexString(key.getKeyID()).substring(8);
                System.out.println("Warning: Signing key (0x"+keyId+") has been revoked");
                // throw new PGPException("Signing key (0x"+keyId+") has been revoked");
            }

            sig.initVerify(key, BouncyCastleProvider.PROVIDER_NAME);

            sig.update(bOut.toByteArray());

            return sig.verify();
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
     * Check a one-pass signature
     */
    private boolean checkOnePassSignature(String outputFilename,
                                          PGPOnePassSignatureList p1,
                                          PGPObjectFactory pgpFact,
                                          PGPPublicKeyRingCollection pgpRing)
        throws PGPException
    {
        try {
            PGPOnePassSignature ops = null;
            PGPPublicKey key = null;

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
            if (key.isRevoked()) {
                String keyId = Long.toHexString(key.getKeyID()).substring(8);
                System.out.println("Warning: Signing key (0x"+keyId+") has been revoked");
                // throw new PGPException("Signing key (0x"+keyId+") has been revoked");
            }

            PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

            if (outputFilename == null)
            {
                outputFilename = ld.getFileName();
            }

            FileOutputStream out = new FileOutputStream(outputFilename);

            InputStream dataIn = ld.getInputStream();

            ops.initVerify(key, BouncyCastleProvider.PROVIDER_NAME);

            int ch;
            while ((ch = dataIn.read()) >= 0)
            {
                ops.update((byte) ch);
                out.write(ch);
            }

            out.close();

            PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

            return ops.verify(p3.get(0));
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
     * Check a signature
     */
    private boolean checkSignature(String outputFilename,
                                   PGPSignatureList sigList,
                                   PGPObjectFactory pgpFact,
                                   PGPPublicKeyRingCollection pgpRing)
        throws PGPException
    {
        try {
            PGPSignature sig = null;
            PGPPublicKey key = null;

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
            if (key.isRevoked()) {
                String keyId = Long.toHexString(key.getKeyID()).substring(8);
                System.out.println("Warning: Signing key (0x"+keyId+") has been revoked");
                // throw new PGPException("Signing key (0x"+keyId+") has been revoked");
            }

            PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

            if (outputFilename == null)
            {
                outputFilename = ld.getFileName();
            }

            FileOutputStream out = new FileOutputStream(outputFilename);

            InputStream dataIn = ld.getInputStream();

            sig.initVerify(key, BouncyCastleProvider.PROVIDER_NAME);

            int ch;
            while ((ch = dataIn.read()) >= 0)
            {
                sig.update((byte) ch);
                out.write(ch);
            }
            out.close();

            return sig.verify();
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
     * Find the public key for the recipient
     */
    private PGPPublicKey readPublicKey(PGPPublicKeyRingCollection pubRing,
                                       String recipient, boolean encrypting)
        throws IOException, PGPException
    {
        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        PGPPublicKey key = null;

        //
        // iterate through the key rings.
        //
        Iterator rIt = pubRing.getKeyRings();

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
            if (encrypting) {
                throw new PGPException("Can't find encryption key in key ring");
            } else {
                throw new PGPException("Can't find signing key in key ring");
            }
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
    private static PGPPublicKey findPublicKey(PGPPublicKeyRingCollection pubRing,
                                              long keyID, boolean encrypting)
        throws IOException, PGPException, NoSuchProviderException
    {
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
     * @param signing indicates whether looking for a signing key.
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    private static PGPSecretKey findSecretKey(PGPSecretKeyRingCollection secRing, long keyID, boolean signing)
        throws IOException, PGPException, NoSuchProviderException
    {
        PGPSecretKey    pgpSecKey = secRing.getSecretKey(keyID);

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
    private static PGPSecretKey findSigningKey(PGPSecretKeyRingCollection secRing)
        throws IOException, PGPException
    {
        //
        // We just loop through the collection till we find a key suitable for encryption.
        //
        PGPSecretKey    key = null;

        Iterator rIt = secRing.getKeyRings();

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
