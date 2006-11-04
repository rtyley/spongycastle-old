package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.StreamParsingException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509StreamParserSpi;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class X509CRLParser
    extends X509StreamParserSpi
{
    private static final long  MAX_MEMORY = Runtime.getRuntime().maxMemory();

    private SignedData sData = null;
    private int         sDataObjectCount = 0;
    private InputStream currentStream = null;

    private int getLimit(InputStream in)
        throws IOException
    {
        if (in instanceof ByteArrayInputStream)
        {
            return in.available();
        }

        if (MAX_MEMORY > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }

        return (int)MAX_MEMORY;
    }

    private String readLine(
        InputStream in)
        throws IOException
    {
        int             c;
        StringBuffer    l = new StringBuffer();

        while (((c = in.read()) != '\n') && (c >= 0))
        {
            if (c == '\r')
            {
                continue;
            }

            l.append((char)c);
        }

        if (c < 0)
        {
            return null;
        }

        return l.toString();
    }

    private CRL readDERCRL(
        InputStream in)
        throws IOException, CRLException
    {
        ASN1InputStream dIn = new ASN1InputStream(in, getLimit(in));
        ASN1Sequence seq = (ASN1Sequence)dIn.readObject();

        if (seq.size() > 1
                && seq.getObjectAt(0) instanceof DERObjectIdentifier)
        {
            if (seq.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData))
            {
                sData = new SignedData(ASN1Sequence.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(1), true));

                return new X509CRLObject(
                            CertificateList.getInstance(
                                    sData.getCertificates().getObjectAt(sDataObjectCount++)));
            }
        }

        return new X509CRLObject(CertificateList.getInstance(seq));
    }

    private CRL readPEMCRL(
        InputStream  in)
        throws IOException, CRLException
    {
        String          line;
        StringBuffer    pemBuf = new StringBuffer();

        while ((line = readLine(in)) != null)
        {
            if (line.equals("-----BEGIN CRL-----")
                || line.equals("-----BEGIN X509 CRL-----"))
            {
                break;
            }
        }

        while ((line = readLine(in)) != null)
        {
            if (line.equals("-----END CRL-----")
                || line.equals("-----END X509 CRL-----"))
            {
                break;
            }

            pemBuf.append(line);
        }

        if (pemBuf.length() != 0)
        {
            return readDERCRL(new ASN1InputStream(Base64.decode(pemBuf.toString())));
        }

        return null;
    }

    public void engineInit(InputStream in)
    {
        currentStream = in;
        sData = null;
        sDataObjectCount = 0;

        if (!currentStream.markSupported())
        {
            currentStream = new BufferedInputStream(currentStream);
        }
    }

    public Object engineRead()
        throws StreamParsingException
    {
        try
        {
            if (sData != null)
            {
                if (sDataObjectCount != sData.getCertificates().size())
                {
                    return new X509CertificateObject(
                                X509CertificateStructure.getInstance(
                                        sData.getCertificates().getObjectAt(sDataObjectCount++)));
                }
                else
                {
                    sData = null;
                    sDataObjectCount = 0;
                    return null;
                }
            }

            currentStream.mark(10);
            int    tag = currentStream.read();

            if (tag == -1)
            {
                return null;
            }

            if (tag != 0x30)  // assume ascii PEM encoded.
            {
                currentStream.reset();
                return readPEMCRL(currentStream);
            }
            else
            {
                currentStream.reset();
                return readDERCRL(currentStream);
            }
        }
        catch (Exception e)
        {
            throw new StreamParsingException(e.toString(), e);
        }
    }

    public Collection engineReadAll()
        throws StreamParsingException
    {
        CRL     crl;
        List certs = new ArrayList();

        while ((crl = (CRL)engineRead()) != null)
        {
            certs.add(crl);
        }

        return certs;
    }
}
