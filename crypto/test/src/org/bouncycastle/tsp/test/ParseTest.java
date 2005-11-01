package org.bouncycastle.tsp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

/**
 * Test Cases
 */
public class ParseTest
    extends TestCase
{
    private byte[] sha1Request = Base64.decode(
          "MDACAQEwITAJBgUrDgMCGgUABBT5UbEBmJssO3RxcQtOePxNvfoMpgIIC+Gv"
        + "YW2mtZQ=");


    private byte[] sha1noNonse = Base64.decode(
        "MCYCAQEwITAJBgUrDgMCGgUABBT5UbEBmJssO3RxcQtOePxNvfoMpg==");

    private byte[] md5Request = Base64.decode(
          "MDoCAQEwIDAMBggqhkiG9w0CBQUABBDIl9FBCvjyx0+6EbHbUR6eBgkrBgEE"
        + "AakHBQECCDQluayIxIzn");

    private byte[] ripemd160Request = Base64.decode(
        "MD8CAQEwITAJBgUrJAMCAQUABBSq03a/mk50Yd9lMF+BSqOp/RHGQQYJKwYB"
      + "BAGpBwUBAgkA4SZs9NfqISMBAf8=");

    private byte[] sha1Response = Base64.decode(
          "MIICbDADAgEAMIICYwYJKoZIhvcNAQcCoIICVDCCAlACAQMxCzAJBgUrDgMC"
        + "GgUAMIHaBgsqhkiG9w0BCRABBKCBygSBxzCBxAIBAQYEKgMEATAhMAkGBSsO"
        + "AwIaBQAEFPlRsQGYmyw7dHFxC054/E29+gymAgEEGA8yMDA0MTIwOTA3NTIw"
        + "NVowCgIBAYACAfSBAWQBAf8CCAvhr2FtprWUoGmkZzBlMRgwFgYDVQQDEw9F"
        + "cmljIEguIEVjaGlkbmExJDAiBgkqhkiG9w0BCQEWFWVyaWNAYm91bmN5Y2Fz"
        + "dGxlLm9yZzEWMBQGA1UEChMNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUx"
        + "ggFfMIIBWwIBATAqMCUxFjAUBgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJBgNV"
        + "BAYTAkFVAgECMAkGBSsOAwIaBQCggYwwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3"
        + "DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0wNDEyMDkwNzUyMDVaMCMGCSqGSIb3"
        + "DQEJBDEWBBTGR1cbm94tWbcpDWrH+bD8UYePsTArBgsqhkiG9w0BCRACDDEc"
        + "MBowGDAWBBS37aLzFcheqeJ5cla0gjNWHGKbRzANBgkqhkiG9w0BAQEFAASB"
        + "gBrc9CJ3xlcTQuWQXJUqPEn6f6vfJAINKsn22z8LIfS/2p/CTFU6+W/bz8j8"
        + "j+8uWEJe8okTsI0FflljIsspqOPTB/RrnXteajbkuk/rLmz1B2g/qWBGAzPI"
        + "D214raBc1a7Bpd76PkvSSdjqrEaaskd+7JJiPr9l9yeSoh1AIt0N");

    private byte[] sha1noNonseResponse = Base64.decode(
          "MIICYjADAgEAMIICWQYJKoZIhvcNAQcCoIICSjCCAkYCAQMxCzAJBgUrDgMC"
        + "GgUAMIHQBgsqhkiG9w0BCRABBKCBwASBvTCBugIBAQYEKgMEATAhMAkGBSsO"
        + "AwIaBQAEFPlRsQGYmyw7dHFxC054/E29+gymAgECGA8yMDA0MTIwOTA3MzQx"
        + "MlowCgIBAYACAfSBAWQBAf+gaaRnMGUxGDAWBgNVBAMTD0VyaWMgSC4gRWNo"
        + "aWRuYTEkMCIGCSqGSIb3DQEJARYVZXJpY0Bib3VuY3ljYXN0bGUub3JnMRYw"
        + "FAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTGCAV8wggFbAgEB"
        + "MCowJTEWMBQGA1UEChMNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUCAQIw"
        + "CQYFKw4DAhoFAKCBjDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJ"
        + "KoZIhvcNAQkFMQ8XDTA0MTIwOTA3MzQxMlowIwYJKoZIhvcNAQkEMRYEFMNA"
        + "xlscHYiByHL9DIEh3FewIhgSMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFLft"
        + "ovMVyF6p4nlyVrSCM1YcYptHMA0GCSqGSIb3DQEBAQUABIGAaj46Tarrg7V7"
        + "z13bbetrGv+xy159eE8kmIW9nPegru3DuK/GmbMx9W3l0ydx0zdXRwYi6NZc"
        + "nNqbEZQZ2L1biJVTflgWq4Nxu4gPGjH/BGHKdH/LyW4eDcXZR39AkNBMnDAK"
        + "EmhhJo1/Tc+S/WkV9lnHJCPIn+TAijBUO6EiTik=");
    
    private byte[] md5Response = Base64.decode(
          "MIICcDADAgEAMIICZwYJKoZIhvcNAQcCoIICWDCCAlQCAQMxCzAJBgUrDgMC"
        + "GgUAMIHeBgsqhkiG9w0BCRABBKCBzgSByzCByAIBAQYJKwYBBAGpBwUBMCAw"
        + "DAYIKoZIhvcNAgUFAAQQyJfRQQr48sdPuhGx21EengIBAxgPMjAwNDEyMDkw"
        + "NzQ2MTZaMAoCAQGAAgH0gQFkAQH/Agg0JbmsiMSM56BppGcwZTEYMBYGA1UE"
        + "AxMPRXJpYyBILiBFY2hpZG5hMSQwIgYJKoZIhvcNAQkBFhVlcmljQGJvdW5j"
        + "eWNhc3RsZS5vcmcxFjAUBgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJBgNVBAYT"
        + "AkFVMYIBXzCCAVsCAQEwKjAlMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQsw"
        + "CQYDVQQGEwJBVQIBAjAJBgUrDgMCGgUAoIGMMBoGCSqGSIb3DQEJAzENBgsq"
        + "hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMDQxMjA5MDc0NjE2WjAjBgkq"
        + "hkiG9w0BCQQxFgQUFpRpaiRUUjiY7EbefbWLKDIY0XMwKwYLKoZIhvcNAQkQ"
        + "AgwxHDAaMBgwFgQUt+2i8xXIXqnieXJWtIIzVhxim0cwDQYJKoZIhvcNAQEB"
        + "BQAEgYBTwKsLLrQm+bvKV7Jwto/cMQh0KsVB5RoEeGn5CI9XyF2Bm+JRcvQL"
        + "Nm7SgSOBVt4A90TqujxirNeyQnXRiSnFvXd09Wet9WIQNpwpiGlE7lCrAhuq"
        + "/TAUe79VIpoQZDtyhbh0Vzxl24yRoechabC0zuPpOWOzrA4YC3Hv1J2tAA==");

    private byte[] signingCert = Base64.decode(
        "MIICWjCCAcOgAwIBAgIBAjANBgkqhkiG9w0BAQQFADAlMRYwFAYDVQQKEw1Cb3Vu"
      + "Y3kgQ2FzdGxlMQswCQYDVQQGEwJBVTAeFw0wNDEyMDkwNzEzMTRaFw0wNTAzMTkw"
      + "NzEzMTRaMGUxGDAWBgNVBAMTD0VyaWMgSC4gRWNoaWRuYTEkMCIGCSqGSIb3DQEJ"
      + "ARYVZXJpY0Bib3VuY3ljYXN0bGUub3JnMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxl"
      + "MQswCQYDVQQGEwJBVTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqGAFO3dK"
      + "jB7Ca7u5Z3CabsbGr2Exg+3sztSPiRCIba03es4295EhtDF5bXQvrW2R1Bg72vED"
      + "5tWaQjVDetvDfCzVC3ErHLTVk3OgpLIP1gf2T0LcOH2pTh2LP9c5Ceta+uggK8zK"
      + "9sYUUnzGPSAZxrqHIIAlPIgqk0BMV+KApyECAwEAAaNaMFgwHQYDVR0OBBYEFO4F"
      + "YoqogtB9MjD0NB5x5HN3TrGUMB8GA1UdIwQYMBaAFPXAecuwLqNkCxYVLE/ngFQR"
      + "7RLIMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBBAUAA4GBADGi"
      + "D5/qmGvcBgswEM/z2dF4lOxbTNKUW31ZHiU8CXlN0IkFtNbBLBTbJOQIAUnNEabL"
      + "T7aYgj813OZKUbJTx4MuGChhot/TEP7hKo/xz9OnXLsqYDKbqbo8iLOode+SI7II"
      + "+yYghOtqvx32cL2Qmffi1LaMbhJP+8NbsIxowdRC");

    private byte[] unacceptablePolicy = Base64.decode(
          "MDAwLgIBAjAkDCJSZXF1ZXN0ZWQgcG9saWN5IGlzIG5vdCBzdXBwb3J0ZWQu"
        + "AwMAAAE=");

    private byte[] generalizedTime = Base64.decode(
        "MIIKPTADAgEAMIIKNAYJKoZIhvcNAQcCoIIKJTCCCiECAQMxCzAJBgUrDgMC"
      + "GgUAMIIBGwYLKoZIhvcNAQkQAQSgggEKBIIBBjCCAQICAQEGCisGAQQBhFkK"
      + "AwEwITAJBgUrDgMCGgUABBQAAAAAAAAAAAAAAAAAAAAAAAAAAAICUC8YEzIw"
      + "MDUwMzEwMTA1ODQzLjkzM1owBIACAfQBAf8CAWSggaikgaUwgaIxCzAJBgNV"
      + "BAYTAkdCMRcwFQYDVQQIEw5DYW1icmlkZ2VzaGlyZTESMBAGA1UEBxMJQ2Ft"
      + "YnJpZGdlMSQwIgYDVQQKExtuQ2lwaGVyIENvcnBvcmF0aW9uIExpbWl0ZWQx"
      + "JzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjozMjJBLUI1REQtNzI1QjEXMBUG"
      + "A1UEAxMOZGVtby1kc2UyMDAtMDGgggaFMIID2TCCA0KgAwIBAgICAIswDQYJ"
      + "KoZIhvcNAQEFBQAwgYwxCzAJBgNVBAYTAkdCMRcwFQYDVQQIEw5DYW1icmlk"
      + "Z2VzaGlyZTESMBAGA1UEBxMJQ2FtYnJpZGdlMSQwIgYDVQQKExtuQ2lwaGVy"
      + "IENvcnBvcmF0aW9uIExpbWl0ZWQxGDAWBgNVBAsTD1Byb2R1Y3Rpb24gVEVT"
      + "VDEQMA4GA1UEAxMHVEVTVCBDQTAeFw0wNDA2MTQxNDIzNTlaFw0wNTA2MTQx"
      + "NDIzNTlaMIGiMQswCQYDVQQGEwJHQjEXMBUGA1UECBMOQ2FtYnJpZGdlc2hp"
      + "cmUxEjAQBgNVBAcTCUNhbWJyaWRnZTEkMCIGA1UEChMbbkNpcGhlciBDb3Jw"
      + "b3JhdGlvbiBMaW1pdGVkMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBFU046MzIy"
      + "QS1CNURELTcyNUIxFzAVBgNVBAMTDmRlbW8tZHNlMjAwLTAxMIGfMA0GCSqG"
      + "SIb3DQEBAQUAA4GNADCBiQKBgQC7zUamCeLIApddx1etW5YEFrL1WXnlCd7j"
      + "mMFI6RpSq056LBkF1z5LgucLY+e/c3u2Nw+XJuS3a2fKuBD7I1s/6IkVtIb/"
      + "KLDjjafOnottKhprH8K41siJUeuK3PRzfZ5kF0vwB3rNvWPCBJmp7kHtUQw3"
      + "RhIsJTYs7Wy8oVFHVwIDAQABo4IBMDCCASwwCQYDVR0TBAIwADAWBgNVHSUB"
      + "Af8EDDAKBggrBgEFBQcDCDAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5l"
      + "cmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFDlEe9Pd0WwQrtnEmFRI2Vmt"
      + "b+lCMIG5BgNVHSMEgbEwga6AFNy1VPweOQLC65bs6/0RcUYB19vJoYGSpIGP"
      + "MIGMMQswCQYDVQQGEwJHQjEXMBUGA1UECBMOQ2FtYnJpZGdlc2hpcmUxEjAQ"
      + "BgNVBAcTCUNhbWJyaWRnZTEkMCIGA1UEChMbbkNpcGhlciBDb3Jwb3JhdGlv"
      + "biBMaW1pdGVkMRgwFgYDVQQLEw9Qcm9kdWN0aW9uIFRFU1QxEDAOBgNVBAMT"
      + "B1RFU1QgQ0GCAQAwDQYJKoZIhvcNAQEFBQADgYEASEMlrpRE1RYZPxP3530e"
      + "hOYUDjgQbw0dwpPjQtLWkeJrePMzDBAbuWwpRI8dOzKP3Rnrm5rxJ7oLY2S0"
      + "A9ZfV+iwFKagEHFytfnPm2Y9AeNR7a3ladKd7NFMw+5Tbk7Asbetbb+NJfCl"
      + "9YzHwxLGiQbpKxgc+zYOjq74eGLKtcKhggKkMIICDQIBATCB0qGBqKSBpTCB"
      + "ojELMAkGA1UEBhMCR0IxFzAVBgNVBAgTDkNhbWJyaWRnZXNoaXJlMRIwEAYD"
      + "VQQHEwlDYW1icmlkZ2UxJDAiBgNVBAoTG25DaXBoZXIgQ29ycG9yYXRpb24g"
      + "TGltaXRlZDEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNOOjMyMkEtQjVERC03"
      + "MjVCMRcwFQYDVQQDEw5kZW1vLWRzZTIwMC0wMaIlCgEBMAkGBSsOAwIaBQAD"
      + "FQDaLe88TQvM+iMKmIXMmDSyPCZ/+KBmMGSkYjBgMQswCQYDVQQGEwJVUzEk"
      + "MCIGA1UEChMbbkNpcGhlciBDb3Jwb3JhdGlvbiBMaW1pdGVkMRgwFgYDVQQL"
      + "Ew9Qcm9kdWN0aW9uIFRlc3QxETAPBgNVBAMTCFRlc3QgVE1DMA0GCSqGSIb3"
      + "DQEBBQUAAgjF2jVbAAAAADAiGA8yMDA1MDMxMDAyNTQxOVoYDzIwMDUwMzEz"
      + "MDI1NDE5WjCBjTBLBgorBgEEAYRZCgQBMT0wOzAMAgTF2jVbAgQAAAAAMA8C"
      + "BAAAAAACBAAAaLkCAf8wDAIEAAAAAAIEAAKV/DAMAgTF3inbAgQAAAAAMD4G"
      + "CisGAQQBhFkKBAIxMDAuMAwGCisGAQQBhFkKAwGgDjAMAgQAAAAAAgQAB6Eg"
      + "oQ4wDAIEAAAAAAIEAAPQkDANBgkqhkiG9w0BAQUFAAOBgQB1q4d3GNWk7oAT"
      + "WkpYmZaTFvapMhTwAmAtSGgFmNOZhs21iHWl/X990/HEBsduwxohfrd8Pz64"
      + "hV/a76rpeJCVUfUNmbRIrsurFx6uKwe2HUHKW8grZWeCD1L8Y1pKQdrD41gu"
      + "v0msfOXzLWW+xe5BcJguKclN8HmT7s2odtgiMTGCAmUwggJhAgEBMIGTMIGM"
      + "MQswCQYDVQQGEwJHQjEXMBUGA1UECBMOQ2FtYnJpZGdlc2hpcmUxEjAQBgNV"
      + "BAcTCUNhbWJyaWRnZTEkMCIGA1UEChMbbkNpcGhlciBDb3Jwb3JhdGlvbiBM"
      + "aW1pdGVkMRgwFgYDVQQLEw9Qcm9kdWN0aW9uIFRFU1QxEDAOBgNVBAMTB1RF"
      + "U1QgQ0ECAgCLMAkGBSsOAwIaBQCgggEnMBoGCSqGSIb3DQEJAzENBgsqhkiG"
      + "9w0BCRABBDAjBgkqhkiG9w0BCQQxFgQUi1iYx5H3ACnvngWZTPfdxGswkSkw"
      + "geMGCyqGSIb3DQEJEAIMMYHTMIHQMIHNMIGyBBTaLe88TQvM+iMKmIXMmDSy"
      + "PCZ/+DCBmTCBkqSBjzCBjDELMAkGA1UEBhMCR0IxFzAVBgNVBAgTDkNhbWJy"
      + "aWRnZXNoaXJlMRIwEAYDVQQHEwlDYW1icmlkZ2UxJDAiBgNVBAoTG25DaXBo"
      + "ZXIgQ29ycG9yYXRpb24gTGltaXRlZDEYMBYGA1UECxMPUHJvZHVjdGlvbiBU"
      + "RVNUMRAwDgYDVQQDEwdURVNUIENBAgIAizAWBBSpS/lH6bN/wf3E2z2X29vF"
      + "2U7YHTANBgkqhkiG9w0BAQUFAASBgGvDVsgsG5I5WKjEDVHvdRwUx+8Cp10l"
      + "zGF8o1h7aK5O3zQ4jLayYHea54E5+df35gG7Z3eoOy8E350J7BvHiwDLTqe8"
      + "SoRlGs9VhL6LMmCcERfGSlSn61Aa15iXZ8eHMSc5JTeJl+kqy4I3FPP4m2ai"
      + "8wy2fQhn7hUM8Ntg7Y2s");

    /* (non-Javadoc)
     * @see org.bouncycastle.util.test.Test#getName()
     */
    public String getName()
    {
        return "ParseTest";
    }

    private void requestParse(
        byte[]  request,
        String  algorithm) 
        throws IOException
    {
        TimeStampRequest    req = new TimeStampRequest(request);
        
        if (!req.getMessageImprintAlgOID().equals(algorithm))
        {
            fail("failed to get expected algorithm - got " 
                    + req.getMessageImprintAlgOID() + " not " + algorithm);
        }
        
        if (request != sha1Request && request != sha1noNonse)
        {
            if (!req.getReqPolicy().equals(TSPTestUtil.EuroPKI_TSA_Test_Policy.getId()))
            {
                fail("" + algorithm + " failed policy check.");
            }
            
            if (request == ripemd160Request)
            {
                if (!req.getCertReq())
                {
                    fail("" + algorithm + " failed certReq check.");
                }
            }
        }
        
        assertEquals("version not 1", 1, req.getVersion());
        
        assertNull("critical extensions found when none expected", req.getCriticalExtensionOIDs());
        
        assertNull("non-critical extensions found when none expected", req.getNonCriticalExtensionOIDs());
        
        if (request != sha1noNonse)
        {
            if (req.getNonce() == null)
            {
                fail("" + algorithm + " nonse not found when one expected.");
            }
        }
        else
        {
            if (req.getNonce() != null)
            {
                fail("" + algorithm + " nonse not found when one not expected.");
            } 
        }
        
        try
        {
            req.validate(TSPAlgorithms.ALLOWED, null, null, "BC");
        }
        catch (Exception e)
        {
            fail("validation exception.");
        }
        
        if (!Arrays.areEqual(req.getEncoded(), request))
        {
            fail("" + algorithm + " failed encode check."); 
        }
    }
    
    private void responseParse(
        byte[]  request,
        byte[]  response,
        String  algorithm) 
        throws Exception
    {
        TimeStampRequest  req = new TimeStampRequest(request);
        TimeStampResponse resp = new TimeStampResponse(response);

        CertificateFactory  fact = CertificateFactory.getInstance("X.509", "BC");
                
        X509Certificate cert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(signingCert));

        resp.validate(req);

        resp.getTimeStampToken().validate(cert, "BC");
    }
    
    private void unacceptableResponseParse(
        byte[]  response) 
        throws Exception
    {
        TimeStampResponse resp = new TimeStampResponse(response);

        if (resp.getStatus() != PKIStatus.REJECTION)
        {
            fail("request not rejected.");
        }
        
        if (resp.getFailInfo().intValue() != PKIFailureInfo.UNACCEPTED_POLICY)
        {
            fail("request not rejected.");
        }
    }
    
    private void generalizedTimeParse(
        byte[]  response) 
        throws Exception
    {
        TimeStampResponse resp = new TimeStampResponse(response);

        if (resp.getStatus() != PKIStatus.GRANTED)
        {
            fail("request not rejected.");
        }
    }
    
    public void testParsing()
        throws Exception
    { 
        requestParse(sha1Request, TSPAlgorithms.SHA1);
        
        requestParse(sha1noNonse, TSPAlgorithms.SHA1);

        requestParse(md5Request, TSPAlgorithms.MD5);

        requestParse(ripemd160Request, TSPAlgorithms.RIPEMD160);

        responseParse(sha1Request, sha1Response, TSPAlgorithms.SHA1);

        responseParse(sha1noNonse, sha1noNonseResponse, TSPAlgorithms.SHA1);

        responseParse(md5Request, md5Response, TSPAlgorithms.MD5);

        unacceptableResponseParse(unacceptablePolicy);

        generalizedTimeParse(generalizedTime);
    }
    
    public void parse(
        byte[]  encoded,
        boolean tokenPresent)
        throws Exception
    {
        TimeStampResponse   response = new TimeStampResponse(encoded);

        if (tokenPresent && response.getTimeStampToken() == null)
        {
            fail("token not found when expected.");
        }
    }
}
