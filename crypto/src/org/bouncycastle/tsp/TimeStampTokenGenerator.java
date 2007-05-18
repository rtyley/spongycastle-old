package org.bouncycastle.tsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.Hashtable;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.tsp.Accuracy;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;

public class TimeStampTokenGenerator
{
    int accuracySeconds = -1;

    int accuracyMillis = -1;

    int accuracyMicros = -1;

    boolean ordering = false;

    GeneralName tsa = null;
    
    private String  tsaPolicyOID;

    PrivateKey      key;
    X509Certificate cert;
    String          digestOID;
    AttributeTable  signedAttr;
    AttributeTable  unsignedAttr;
    CertStore       certsAndCrls;
    
    /**
     * basic creation - only the default attributes will be included here.
     */
    public TimeStampTokenGenerator(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        String          tsaPolicyOID)
        throws IllegalArgumentException, TSPException
    {
        this(key, cert, digestOID, tsaPolicyOID, null, null);
    }

    /**
     * create with a signer with extra signed/unsigned attributes.
     */
    public TimeStampTokenGenerator(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        String          tsaPolicyOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException, TSPException
    {   
        this.key = key;
        this.cert = cert;
        this.digestOID = digestOID;
        this.tsaPolicyOID = tsaPolicyOID;
        this.unsignedAttr = unsignedAttr;
        
        TSPUtil.validateCertificate(cert);

        //
        // add the essCertid
        //
        Hashtable signedAttrs = null;
        
        if (signedAttr != null)
        {
            signedAttrs = signedAttr.toHashtable();
        }
        else
        {
            signedAttrs = new Hashtable();
        }
        
        try
        {
            ESSCertID essCertid = new ESSCertID(MessageDigest.getInstance("SHA-1").digest(cert.getEncoded()));
            signedAttrs.put(PKCSObjectIdentifiers.id_aa_signingCertificate,
                    new Attribute(
                            PKCSObjectIdentifiers.id_aa_signingCertificate,
                            new DERSet(new SigningCertificate(essCertid))));
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new TSPException("Can't find a SHA-1 implementation.", e);
        }
        catch (CertificateEncodingException e)
        {
            throw new TSPException("Exception processing certificate.", e);
        }
        
        this.signedAttr = new AttributeTable(signedAttrs);
    }
    
    public void setCertificatesAndCRLs(CertStore certificates)
            throws CertStoreException, TSPException
    {
        this.certsAndCrls = certificates;
    }

    public void setAccuracySeconds(int accuracySeconds)
    {
        this.accuracySeconds = accuracySeconds;
    }

    public void setAccuracyMillis(int accuracyMillis)
    {
        this.accuracyMillis = accuracyMillis;
    }

    public void setAccuracyMicros(int accuracyMicros)
    {
        this.accuracyMicros = accuracyMicros;
    }

    public void setOrdering(boolean ordering)
    {
        this.ordering = ordering;
    }

    public void setTSA(GeneralName tsa)
    {
        this.tsa = tsa;
    }
    
    //------------------------------------------------------------------------------

    public TimeStampToken generate(
        TimeStampRequest    request,
        BigInteger          serialNumber,
        Date                genTime,
        String              provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, TSPException
    {
        DERObjectIdentifier digestAlgOID = new DERObjectIdentifier(request.getMessageImprintAlgOID());

        AlgorithmIdentifier algID = new AlgorithmIdentifier(digestAlgOID, new DERNull());
        MessageImprint      messageImprint = new MessageImprint(algID, request.getMessageImprintDigest());

        Accuracy accuracy = null;
        if (accuracySeconds > 0 || accuracyMillis > 0 || accuracyMicros > 0)
        {
            DERInteger seconds = null;
            if (accuracySeconds > 0)
            {
                seconds = new DERInteger(accuracySeconds);
            }

            DERInteger millis = null;
            if (accuracyMillis > 0)
            {
                millis = new DERInteger(accuracyMillis);
            }

            DERInteger micros = null;
            if (accuracyMicros > 0)
            {
                micros = new DERInteger(accuracyMicros);
            }

            accuracy = new Accuracy(seconds, millis, micros);
        }

        DERBoolean derOrdering = null;
        if (ordering)
        {
            derOrdering = new DERBoolean(ordering);
        }
        
        DERInteger  nonce = null;
        if (request.getNonce() != null)
        {
            nonce = new DERInteger(request.getNonce());
        }

        DERObjectIdentifier tsaPolicy = new DERObjectIdentifier(tsaPolicyOID);
        if (request.getReqPolicy() != null)
        {
            tsaPolicy = new DERObjectIdentifier(request.getReqPolicy());
        }
        
        TSTInfo tstInfo = new TSTInfo(tsaPolicy,
                messageImprint, new DERInteger(serialNumber),
                new DERGeneralizedTime(genTime), accuracy, derOrdering,
                nonce, tsa, request.getExtensions());
        
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);

        try
        {
            CMSSignedDataGenerator  signedDataGenerator = new CMSSignedDataGenerator();
            
            dOut.writeObject(tstInfo);

            // TODO Check for certsAndCrls != null here?

            CertStore genCertStore;
            if (request.getCertReq())
            {
                genCertStore = certsAndCrls;
            }
            else
            {
                genCertStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certsAndCrls.getCRLs(null)));
            }

            signedDataGenerator.addCertificatesAndCRLs(genCertStore);
            signedDataGenerator.addSigner(key, cert, digestOID, signedAttr, unsignedAttr);

            CMSSignedData signedData = signedDataGenerator.generate(PKCSObjectIdentifiers.id_ct_TSTInfo.getId(), new CMSProcessableByteArray(bOut.toByteArray()), true, provider);
            
            return new TimeStampToken(signedData);
        }
        catch (CMSException cmsEx)
        {
            throw new TSPException("Error generating time-stamp token", cmsEx);
        }
        catch (IOException e)
        {
            throw new TSPException("Exception encoding info", e);
        }
        catch (CertStoreException e)
        {
            throw new TSPException("Exception handling CertStore", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new TSPException("Exception handling CertStore CRLs", e);
        }
    }
}
