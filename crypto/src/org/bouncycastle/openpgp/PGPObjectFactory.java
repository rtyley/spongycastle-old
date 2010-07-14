package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PacketTags;

/**
 * General class for reading a PGP object stream.
 * <p>
 * Note: if this class finds a PGPPublicKey or a PGPSecretKey it
 * will create a PGPPublicKeyRing, or a PGPSecretKeyRing for each
 * key found. If all you are trying to do is read a key ring file use
 * either PGPPublicKeyRingCollection or PGPSecretKeyRingCollection.
 */
public class PGPObjectFactory
{
    BCPGInputStream in;
    
    public PGPObjectFactory(
        InputStream in)
    {
        this.in = new BCPGInputStream(in);
    }
    
    public PGPObjectFactory(
        byte[] bytes)
    {
        this(new ByteArrayInputStream(bytes));
    }
    
    /**
     * Return the next object in the stream, or null if the end is reached.
     * 
     * @return Object
     * @throws IOException on a parse error
     */
    public Object nextObject()
        throws IOException
    {
        List l;

        switch (in.nextPacketTag())
        {
        case -1:
            return null;
        case PacketTags.SIGNATURE:
            l = new ArrayList();
            
            while (in.nextPacketTag() == PacketTags.SIGNATURE)
            {
                try
                {
                    l.add(new PGPSignature(in));
                }
                catch (PGPException e)
                {
                    throw new IOException("can't create signature object: " + e);
                }
            }
            
            return new PGPSignatureList((PGPSignature[])l.toArray(new PGPSignature[l.size()]));
        case PacketTags.SECRET_KEY:
            try
            {
                return new PGPSecretKeyRing(in);
            }
            catch (PGPException e)
            {
                throw new IOException("can't create secret key object: " + e);
            }
        case PacketTags.PUBLIC_KEY:
            return new PGPPublicKeyRing(in);
        case PacketTags.PUBLIC_SUBKEY:
            return PGPPublicKeyRing.readSubkey(in);
        case PacketTags.COMPRESSED_DATA:
            return new PGPCompressedData(in);
        case PacketTags.LITERAL_DATA:
            return new PGPLiteralData(in);
        case PacketTags.PUBLIC_KEY_ENC_SESSION:
        case PacketTags.SYMMETRIC_KEY_ENC_SESSION:
            return new PGPEncryptedDataList(in);
        case PacketTags.ONE_PASS_SIGNATURE:
            l = new ArrayList();
            
            while (in.nextPacketTag() == PacketTags.ONE_PASS_SIGNATURE)
            {
                try
                {
                    l.add(new PGPOnePassSignature(in));
                }
                catch (PGPException e)
                {
                    throw new IOException("can't create one pass signature object: " + e);
                }
            }
            
            return new PGPOnePassSignatureList((PGPOnePassSignature[])l.toArray(new PGPOnePassSignature[l.size()]));
        case PacketTags.MARKER:
            return new PGPMarker(in);
        case PacketTags.EXPERIMENTAL_1:
        case PacketTags.EXPERIMENTAL_2:
        case PacketTags.EXPERIMENTAL_3:
        case PacketTags.EXPERIMENTAL_4:
            return in.readPacket();
        }
        
        throw new IOException("unknown object in stream: " + in.nextPacketTag());
    }
}
