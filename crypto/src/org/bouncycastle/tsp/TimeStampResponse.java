package org.bouncycastle.tsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.MessageDigest;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;

/**
 * Base class for an RFC 3161 Time Stamp Response object.
 */
public class TimeStampResponse
{
    TimeStampResp   resp;
    TimeStampToken  timeStampToken;

    public TimeStampResponse(TimeStampResp resp)
        throws TSPException, IOException
    {
        this.resp = resp;
        
        if (resp.getTimeStampToken() != null)
        {
            timeStampToken = new TimeStampToken(resp.getTimeStampToken());
        }
    }

    public TimeStampResponse(byte[] req)
        throws TSPException, IOException
    {
        this(new ByteArrayInputStream(req));
    }

    public TimeStampResponse(InputStream in)
        throws TSPException, IOException
    {
        this(TimeStampResp.getInstance(new ASN1InputStream(in).readObject()));
    }

    public int getStatus()
    {
        return resp.getStatus().getStatus().intValue();
    }

    public String getStatusString()
    {
        if (resp.getStatus().getStatusString() != null)
        {
            StringBuffer statusStringBuf = new StringBuffer();
            PKIFreeText text = resp.getStatus().getStatusString();
            for (int i = 0; i != text.size(); i++)
            {
                statusStringBuf.append(text.getStringAt(i).getString());
            }
            return statusStringBuf.toString();
        }
        else
        {
            return null;
        }
    }

    public PKIFailureInfo getFailInfo()
    {
        if (resp.getStatus().getFailInfo() != null)
        {
            return new PKIFailureInfo(resp.getStatus().getFailInfo());
        }
        
        return null;
    }

    public TimeStampToken getTimeStampToken()
    {
        return timeStampToken;
    }

    /**
     * Check this response against to see if it a well formed response for 
     * the passed in request. Validation will include checking the time stamp
     * token if the response status is GRANTED or GRANTED_WITH_MODS.
     * 
     * @param request the request to be checked against
     * @throws TSPException if the request can not match this response.
     */
    public void validate(
        TimeStampRequest    request)
        throws TSPException
    {
        TimeStampToken tok = this.getTimeStampToken();
        
        if (tok != null)
        {
            TimeStampTokenInfo  tstInfo = tok.getTimeStampInfo();
            
            if (request.getNonce() != null && !request.getNonce().equals(tstInfo.getNonce()))
            {
                throw new TSPValidationException("response contains wrong nonce value.");
            }
            
            if (this.getStatus() != PKIStatus.GRANTED && this.getStatus() != PKIStatus.GRANTED_WITH_MODS)
            {
                throw new TSPValidationException("time stamp token found in failed request.");
            }
            
            if (!MessageDigest.isEqual(request.getMessageImprintDigest(), tstInfo.getMessageImprintDigest()))
            {
                throw new TSPValidationException("response for different message imprint digest.");
            }
            
            if (!tstInfo.getMessageImprintAlgOID().equals(request.getMessageImprintAlgOID()))
            {
                throw new TSPValidationException("response for different message imprint algorithm.");
            }
            
            if (tok.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificate) == null)
            {
                throw new TSPValidationException("no signing certificate attribute present.");
            }
            
            if (request.getReqPolicy() != null && !request.getReqPolicy().equals(tstInfo.getPolicy()))
            {
                throw new TSPValidationException("TSA policy wrong for request.");
            }
        }
        else if (this.getStatus() == PKIStatus.GRANTED || this.getStatus() == PKIStatus.GRANTED_WITH_MODS)
        {
            throw new TSPValidationException("no time stamp token found and one expected.");
        }
    }
    
    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded() throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(resp);

        return bOut.toByteArray();
    }
}