package org.bouncycastle.openpgp;

import java.util.Date;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignerUserID;

/**
 * Container for a list of signature subpackets.
 */
public class PGPSignatureSubpacketVector
{
    SignatureSubpacket[]    packets;
    
    PGPSignatureSubpacketVector(
        SignatureSubpacket[]    packets)
    {
        this.packets = packets;
    }
    
    public SignatureSubpacket getSubpacket(
        int    type)
    {
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].getType() == type)
            {
                return packets[i];
            }
        }
        
        return null;
    }
    
    public long getIssuerKeyID()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.ISSUER_KEY_ID);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((IssuerKeyID)p).getKeyID();
    }
    
    public Date getSignatureCreationTime()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.CREATION_TIME);
        
        if (p == null)
        {
            return null;
        }
        
        return ((SignatureCreationTime)p).getTime();
    }
    
    /**
     * Return the number of seconds a signature is valid for after its creation date. A value of zero means
     * the key never expires.
     * 
     * @return seconds a signature is valid for.
     */
    public long getSignatureExpirationTime()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.EXPIRE_TIME);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((SignatureExpirationTime)p).getTime();
    }
    
    /**
     * Return the number of seconds a key is valid for after its creation date. A value of zero means
     * the key never expires.
     * 
     * @return seconds a key is valid for.
     */
    public long getKeyExpirationTime()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.KEY_EXPIRE_TIME);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((KeyExpirationTime)p).getTime();
    }
    
    public int[] getPreferredHashAlgorithms()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.PREFERRED_HASH_ALGS);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((PreferredAlgorithms)p).getPreferrences();
    }
    
    public int[] getPreferredSymmetricAlgorithms()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((PreferredAlgorithms)p).getPreferrences();
    }
    
    public int[] getPreferredCompressionAlgorithms()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.PREFERRED_COMP_ALGS);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((PreferredAlgorithms)p).getPreferrences();
    }
    
    public int getKeyFlags()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.KEY_FLAGS);
        
        if (p == null)
        {
            return 0;
        }
                    
        return ((KeyFlags)p).getFlags();
    }
    
    public String getSignerUserID()
    {
        SignatureSubpacket    p = this.getSubpacket(SignatureSubpacketTags.SIGNER_USER_ID);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((SignerUserID)p).getID();
    }
    
    public int[] getCriticalTags()
    {
        int    count = 0;
        
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].isCritical())
            {
                count++;
            }
        }
        
        int[]    list = new int[count];
        
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].isCritical())
            {
                list[i] = packets[i].getType();
            }
        }
        
        return list;
    }
    
    SignatureSubpacket[] toSubpacketArray()
    {
        return packets;
    }
}
