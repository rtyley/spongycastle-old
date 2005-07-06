package org.bouncycastle.openpgp;

import java.util.ArrayList;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;

/**
 * Generator for signature subpackets.
 */
public class PGPSignatureSubpacketGenerator
{
    ArrayList    list = new ArrayList();
    
    public PGPSignatureSubpacketGenerator()
    {
    }
    
    public void setRevocable(
        boolean     isCritical,
        boolean     isRevocable)
    {
        list.add(new Revocable(isCritical, isRevocable));
    }
    
    public void setExportable(
        boolean     isCritical,
        boolean     isExportable)
    {
        list.add(new Exportable(isCritical, isExportable));
    }
    
    public void setTrust(
        boolean     isCritical,
        int         depth,
        int         trustAmount)
    {
        list.add(new TrustSignature(isCritical, depth, trustAmount));
    }
    
    /**
     * Set  the number of seconds a key is valid for after the time of its creation.
     * A value of zero means the key never expires.
     * 
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param seconds
     */
    public void setKeyExpirationTime(
        boolean     isCritical,
        long        seconds)
    {
        list.add(new KeyExpirationTime(isCritical, seconds));
    }
    
    /**
     * Set  the number of seconds a signature is valid for after the time of its creation.
     * A value of zero means the signature never expires.
     * 
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param seconds
     */
    public void setSignatureExpirationTime(
        boolean     isCritical,
        long        seconds)
    {
        list.add(new SignatureExpirationTime(isCritical, seconds));
    }
    
    public void setPreferredHashAlgorithms(
        boolean     isCritical,
        int[]       algorithms)
    {
        list.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_HASH_ALGS, isCritical, algorithms));
    }
    
    public void setPreferredSymmetricAlgorithms(
        boolean     isCritical,
        int[]       algorithms)
    {
        list.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_SYM_ALGS, isCritical, algorithms));
    }
    
    public void setPreferredCompressionAlgorithms(
        boolean     isCritical,
        int[]       algorithms)
    {
        list.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_COMP_ALGS, isCritical, algorithms));
    }
    
    public void setKeyFlags(
        boolean     isCritical,
        int         flags)
    {
        list.add(new KeyFlags(isCritical, flags));
    }
    
    public void setSignerUserID(
        boolean     isCritical,
        String      userID)
    {
        if (userID == null)
        {
            throw new IllegalArgumentException("attempt to set null SignerUserID");
        }
        
        list.add(new SignerUserID(isCritical, userID));
    }
    
    public void setPrimaryUserID(
        boolean     isCritical,
        boolean     isPrimaryUserID)
    {
        list.add(new PrimaryUserID(isCritical, isPrimaryUserID));
    }
    
    public PGPSignatureSubpacketVector generate()
    {
        return new PGPSignatureSubpacketVector((SignatureSubpacket[])list.toArray(new SignatureSubpacket[list.size()]));
    }
}