package org.spongycastle.operator.bc;

import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.MD4Digest;
import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.operator.OperatorCreationException;

class BcUtil
{
    static Digest createDigest(AlgorithmIdentifier digAlg)
        throws OperatorCreationException
    {
        Digest dig;

        if (digAlg.getAlgorithm().equals(OIWObjectIdentifiers.idSHA1))
        {
            dig = new SHA1Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha224))
        {
            dig = new SHA224Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha256))
        {
            dig = new SHA256Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha384))
        {
            dig = new SHA384Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha512))
        {
            dig = new SHA384Digest();
        }
        else if (digAlg.getAlgorithm().equals(PKCSObjectIdentifiers.md5))
        {
            dig = new MD5Digest();
        }
        else if (digAlg.getAlgorithm().equals(PKCSObjectIdentifiers.md4))
        {
            dig = new MD4Digest();
        }
        else
        {
            throw new OperatorCreationException("cannot recognise digest");
        }

        return dig;
    }
}
