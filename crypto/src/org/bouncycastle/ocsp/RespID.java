package org.bouncycastle.ocsp;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.X509Principal;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;

/**
 * Carrier for a ResponderID.
 */
public class RespID
{
    ResponderID id;

    public RespID(
        ResponderID id)
    {
        this.id = id;
    }

    public RespID(
        X500Principal   name)
    {
        try
        {
            this.id = new ResponderID(new X509Principal(name.getEncoded()));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("can't decode name.");
        }
    }

    public RespID(
        PublicKey   key)
        throws OCSPException
    {
        try
        {
            MessageDigest       digest = MessageDigest.getInstance("SHA1");

            ASN1InputStream aIn = new ASN1InputStream(key.getEncoded());
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(aIn.readObject());

            digest.update(info.getPublicKeyData().getBytes());

            ASN1OctetString keyHash = new DEROctetString(digest.digest());

            this.id = new ResponderID(keyHash);
        }
        catch (Exception e)
        {
            throw new OCSPException("problem creating ID: " + e, e);
        }
    }

    public ResponderID toASN1Object()
    {
        return id;
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof RespID))
        {
            return false;
        }

        RespID   obj = (RespID)o;

        return id.equals(obj.id);
    }

    public int hashCode()
    {
        return id.hashCode();
    }
}
