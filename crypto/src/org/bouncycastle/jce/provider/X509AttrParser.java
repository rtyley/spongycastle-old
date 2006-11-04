package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.util.StreamParsingException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509StreamParserSpi;
import org.bouncycastle.x509.X509V2AttributeCertificate;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class X509AttrParser
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

    private X509AttributeCertificate readDERCertificate(
        InputStream in)
        throws IOException
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

                return getCertificate();
            }
        }

        return new X509V2AttributeCertificate(seq.getEncoded());
    }

    private X509AttributeCertificate getCertificate()
        throws IOException
    {
        try
        {
            return new X509V2AttributeCertificate(
                      ASN1Sequence.getInstance(sData.getCertificates().getObjectAt(sDataObjectCount++)).getEncoded());
        }
        catch (IllegalArgumentException e)       // could be an attribute certificate
        {
            if (sDataObjectCount < sData.getCertificates().size())
            {
                return getCertificate();
            }
        }

        return null;
    }

    private X509AttributeCertificate readPEMCertificate(
        InputStream  in)
        throws IOException
    {
        String          line;
        StringBuffer    pemBuf = new StringBuffer();

        while ((line = readLine(in)) != null)
        {
            if (line.equals("-----BEGIN ATTRIBUTE CERTIFICATE-----")
                || line.equals("-----BEGIN X509 ATTRIBUTE CERTIFICATE-----"))
            {
                break;
            }
        }

        while ((line = readLine(in)) != null)
        {
            if (line.equals("-----END ATTRIBUTE CERTIFICATE-----")
                || line.equals("-----END X509 ATTRIBUTE CERTIFICATE-----"))
            {
                break;
            }

            pemBuf.append(line);
        }

        if (pemBuf.length() != 0)
        {
            return readDERCertificate(new ASN1InputStream(Base64.decode(pemBuf.toString())));
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
                    return getCertificate();
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
                return readPEMCertificate(currentStream);
            }
            else
            {
                currentStream.reset();
                return readDERCertificate(currentStream);
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
        X509AttributeCertificate cert;
        List certs = new ArrayList();

        while ((cert = (X509AttributeCertificate)engineRead()) != null)
        {
            certs.add(cert);
        }

        return certs;
    }
}
