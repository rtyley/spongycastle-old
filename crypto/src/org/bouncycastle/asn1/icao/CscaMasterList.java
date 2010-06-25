package org.bouncycastle.asn1.icao;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * The CscaMasterList object. This object can be wrapped in a
 * CMSSignedData to be published in LDAP.
 *
 * <pre>
 * CscaMasterList ::= SEQUENCE {
 *   version                CscaMasterListVersion,
 *   certList               SET OF Certificate }
 *   
 * CscaMasterListVersion :: INTEGER {v0(0)}
 * </pre>
 */

public class CscaMasterList 
    extends ASN1Encodable 
{
    private DERInteger version = new DERInteger(0);
    private X509CertificateStructure[] certList;

    public static CscaMasterList getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof CscaMasterList)
        {
            return (CscaMasterList)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new CscaMasterList(ASN1Sequence.getInstance(obj));            
        }
        
        throw new IllegalArgumentException(
                "unknown object in getInstance: " + obj.getClass().getName());
    }    
    
    public CscaMasterList(
        ASN1Sequence seq)
    {
        if (seq == null || seq.size() == 0)
        {
            throw new IllegalArgumentException(
                    "null or empty sequence passed.");
        }
        if (seq.size() != 2) {
            throw new IllegalArgumentException(
                    "Incorrect sequence size: " + seq.size());
        }
        
        version = DERInteger.getInstance(seq.getObjectAt(0));
        ASN1Set certSet = ASN1Set.getInstance(seq.getObjectAt(1));
        certList = new X509CertificateStructure[certSet.size()];
        for (int i = 0; i < certList.length; i++) {
            certList[i]
                = X509CertificateStructure.getInstance(certSet.getObjectAt(i));
        }
    }

    public CscaMasterList(
        X509CertificateStructure[] certStructs)
    {
        certList = certStructs.clone();
    }

    public CscaMasterList(
        X509Certificate[] certs)
    {
        certList = new X509CertificateStructure[certs.length];
        for (int i = 0; i < certList.length; i++) {
            try {
                certList[i]
                    = X509CertificateStructure.getInstance(
                        ASN1Object.fromByteArray(certs[i].getEncoded()));
            }
            catch (Exception e) {
                throw new IllegalArgumentException(
                    "Failed to parse encoded certificate", e);
            }
        }
    }

    public int getVersion() {
        return version.getValue().intValue();
    }

    public X509CertificateStructure[] getCertStructs()
    {
        return certList.clone();
    }

    public X509Certificate[] getCerts() throws CertificateParsingException {
        X509Certificate[] certs = new X509Certificate[certList.length];
        for (int i = 0; i < certs.length; i++) {
            certs[i] = new X509CertificateObject(certList[i]);
        }
        return certs;
    }

    public DERObject toASN1Object() 
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();

        seq.add(version);

        ASN1EncodableVector certSet = new ASN1EncodableVector();
        for (int i = 0; i < certList.length; i++) 
        {
            certSet.add(certList[i]);
        }            
        seq.add(new DERSet(certSet));                   

        return new DERSequence(seq);
    }          
}
