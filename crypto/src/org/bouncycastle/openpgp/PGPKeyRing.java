package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserIDPacket;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

public abstract class PGPKeyRing
{
    PGPKeyRing()
    {
    }

    static BCPGInputStream wrap(InputStream in)
    {
        if (in instanceof BCPGInputStream)
        {
            return (BCPGInputStream)in;
        }

        return new BCPGInputStream(in);
    }

    static TrustPacket readOptionalTrustPacket(
        BCPGInputStream pIn)
        throws IOException
    {
        return (pIn.nextPacketTag() == PacketTags.TRUST)
            ?   (TrustPacket) pIn.readPacket()
            :   null;
    }

    static ArrayList readSignaturesAndTrust(
        BCPGInputStream pIn)
        throws IOException
    {
        try
        {
            ArrayList sigList = new ArrayList();

            while (pIn.nextPacketTag() == PacketTags.SIGNATURE)
            {
                SignaturePacket signaturePacket = (SignaturePacket) pIn.readPacket();
                TrustPacket trustPacket = readOptionalTrustPacket(pIn);

                sigList.add(new PGPSignature(signaturePacket, trustPacket));
            }

            return sigList;
        }
        catch (PGPException e)
        {
            throw new IOException("can't create signature object: " + e.getMessage()
                + ", cause: " + e.getUnderlyingException().toString());
        }
    }

    static void readUserIDs(
        BCPGInputStream pIn,
        ArrayList ids,
        ArrayList idTrusts,
        ArrayList idSigs)
        throws IOException
    {
        while (pIn.nextPacketTag() == PacketTags.USER_ID
            || pIn.nextPacketTag() == PacketTags.USER_ATTRIBUTE)
        {
            Packet obj = pIn.readPacket();
            if (obj instanceof UserIDPacket)
            {
                UserIDPacket id = (UserIDPacket)obj;
                ids.add(id.getID());
            }
            else
            {
                UserAttributePacket user = (UserAttributePacket) obj;
                ids.add(new PGPUserAttributeSubpacketVector(user.getSubpackets()));
            }

            idTrusts.add(readOptionalTrustPacket(pIn));
            idSigs.add(readSignaturesAndTrust(pIn));
        }
    }
}
