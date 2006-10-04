package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class X509LDAPCertStoreTest
    extends SimpleTest
{
    private byte cert1[] = Base64
            .decode("MIIDyTCCAzKgAwIBAgIEL64+8zANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJE"
                    + "RTEcMBoGA1UEChQTRGV1dHNjaGUgVGVsZWtvbSBBRzEoMAwGBwKCBgEKBxQTATEw"
                    + "GAYDVQQDFBFUVEMgVGVzdCBDQSAxMTpQTjAeFw0wMzAzMjUxNDM1MzFaFw0wNjAz"
                    + "MjUxNDM1MzFaMGIxCzAJBgNVBAYTAkRFMRswGQYDVQQKDBJHRlQgU29sdXRpb25z"
                    + "IEdtYkgxEjAQBgNVBAsMCUhZUEFSQ0hJVjEWMBQGA1UEAwwNRGllZ2UsIFNpbW9u"
                    + "ZTEKMAgGA1UEBRMBMTCBoDANBgkqhkiG9w0BAQEFAAOBjgAwgYoCgYEAiEYsFbs4"
                    + "FesQpMjBkzJB92c0p8tJ02nbCNA5l17VVbbrv6/twnQHW4kgA+9lZlXfzI8iunT1"
                    + "KuiwVupWObHgFaGPkelIN/qIbuwbQzh7T+IUKdKETE12Lc+xk9YvQ6mJVgosmwpr"
                    + "nMMjezymh8DjPhe7MC7/H3AotrHVNM3mEJcCBEAAAIGjggGWMIIBkjAfBgNVHSME"
                    + "GDAWgBTQc8wTeltcAM3iTE63fk/wTA+IJTAdBgNVHQ4EFgQUq6ChBvXPiqhMHLS3"
                    + "kiKpSeGWDz4wDgYDVR0PAQH/BAQDAgQwMB8GA1UdEQQYMBaBFHNpbW9uZS5kaWVn"
                    + "ZUBnZnQuY29tMIHoBgNVHR8EgeAwgd0wgdqgaqBohjVsZGFwOi8vcGtzbGRhcC50"
                    + "dHRjLmRlOjM4OS9jPWRlLG89RGV1dHNjaGUgVGVsZWtvbSBBR4YvaHR0cDovL3d3"
                    + "dy50dHRjLmRlL3RlbGVzZWMvc2VydmxldC9kb3dubG9hZF9jcmyibKRqMGgxCzAJ"
                    + "BgNVBAYTAkRFMRwwGgYDVQQKFBNEZXV0c2NoZSBUZWxla29tIEFHMTswDAYHAoIG"
                    + "AQoHFBMBMTArBgNVBAMUJFRlbGVTZWMgRGlyZWN0b3J5IFNlcnZpY2UgU2lnRyAx"
                    + "MDpQTjA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly93d3cudHR0"
                    + "Yy5kZS9vY3NwcjANBgkqhkiG9w0BAQUFAAOBgQBCPudAtrP9Bx7GRhHQgYS6kaoN"
                    + "vYb/yDss86pyn0uiFuwT+mT1popcAfxPo2yxL0jqqlsDNFBC2hJob5rjihsKPmqV"
                    + "rSaW0VJu/zBihsX7hLKOVMf5gvUYMS5ulq/bp8jOj8a+5SmxVY+WWZVFghWjISse"
                    + "T3WABdTS9S3zjnQiyg==");

    byte[] directCRL = Base64.decode(
            "MIIGXTCCBckCAQEwCgYGKyQDAwECBQAwdDELMAkGA1UEBhMCREUxHDAaBgNVBAoU"
            +"E0RldXRzY2hlIFRlbGVrb20gQUcxFzAVBgNVBAsUDlQtVGVsZVNlYyBUZXN0MS4w"
            +"DAYHAoIGAQoHFBMBMTAeBgNVBAMUF1QtVGVsZVNlYyBUZXN0IERJUiA4OlBOFw0w"
            +"NjA4MDQwODQ1MTRaFw0wNjA4MDQxNDQ1MTRaMIIElTAVAgQvrj/pFw0wMzA3MjIw"
            +"NTQxMjhaMBUCBC+uP+oXDTAzMDcyMjA1NDEyOFowFQIEL64/5xcNMDQwNDA1MTMx"
            +"ODE3WjAVAgQvrj/oFw0wNDA0MDUxMzE4MTdaMBUCBC+uP+UXDTAzMDExMzExMTgx"
            +"MVowFQIEL64/5hcNMDMwMTEzMTExODExWjAVAgQvrj/jFw0wMzAxMTMxMTI2NTZa"
            +"MBUCBC+uP+QXDTAzMDExMzExMjY1NlowFQIEL64/4hcNMDQwNzEzMDc1ODM4WjAV"
            +"AgQvrj/eFw0wMzAyMTcwNjMzMjVaMBUCBC+uP98XDTAzMDIxNzA2MzMyNVowFQIE"
            +"L64/0xcNMDMwMjE3MDYzMzI1WjAVAgQvrj/dFw0wMzAxMTMxMTI4MTRaMBUCBC+u"
            +"P9cXDTAzMDExMzExMjcwN1owFQIEL64/2BcNMDMwMTEzMTEyNzA3WjAVAgQvrj/V"
            +"Fw0wMzA0MzAxMjI3NTNaMBUCBC+uP9YXDTAzMDQzMDEyMjc1M1owFQIEL64/xhcN"
            +"MDMwMjEyMTM0NTQwWjAVAgQvrj/FFw0wMzAyMTIxMzQ1NDBaMBUCBC+uP8IXDTAz"
            +"MDIxMjEzMDkxNlowFQIEL64/wRcNMDMwMjEyMTMwODQwWjAVAgQvrj++Fw0wMzAy"
            +"MTcwNjM3MjVaMBUCBC+uP70XDTAzMDIxNzA2MzcyNVowFQIEL64/sBcNMDMwMjEy"
            +"MTMwODU5WjAVAgQvrj+vFw0wMzAyMTcwNjM3MjVaMBUCBC+uP5MXDTAzMDQxMDA1"
            +"MjYyOFowFQIEL64/khcNMDMwNDEwMDUyNjI4WjAVAgQvrj8/Fw0wMzAyMjYxMTA0"
            +"NDRaMBUCBC+uPz4XDTAzMDIyNjExMDQ0NFowFQIEL64+zRcNMDMwNTIwMDUyNzM2"
            +"WjAVAgQvrj7MFw0wMzA1MjAwNTI3MzZaMBUCBC+uPjwXDTAzMDYxNzEwMzQxNlow"
            +"FQIEL64+OxcNMDMwNjE3MTAzNDE2WjAVAgQvrj46Fw0wMzA2MTcxMDM0MTZaMBUC"
            +"BC+uPjkXDTAzMDYxNzEzMDEwMFowFQIEL64+OBcNMDMwNjE3MTMwMTAwWjAVAgQv"
            +"rj43Fw0wMzA2MTcxMzAxMDBaMBUCBC+uPjYXDTAzMDYxNzEzMDEwMFowFQIEL64+"
            +"MxcNMDMwNjE3MTAzNzQ5WjAVAgQvrj4xFw0wMzA2MTcxMDQyNThaMBUCBC+uPjAX"
            +"DTAzMDYxNzEwNDI1OFowFQIEL649qRcNMDMxMDIyMTEzMjI0WjAVAgQvrjyyFw0w"
            +"NTAzMTEwNjQ0MjRaMBUCBC+uPKsXDTA0MDQwMjA3NTQ1M1owFQIEL6466BcNMDUw"
            +"MTI3MTIwMzI0WjAVAgQvrjq+Fw0wNTAyMTYwNzU3MTZaMBUCBC+uOqcXDTA1MDMx"
            +"MDA1NTkzNVowFQIEL646PBcNMDUwNTExMTA0OTQ2WjAVAgQvrG3VFw0wNTExMTEx"
            +"MDAzMjFaMBUCBC+uLmgXDTA2MDEyMzEwMjU1NVowFQIEL64mxxcNMDYwODAxMDk0"
            +"ODQ0WqCBijCBhzALBgNVHRQEBAICEQwwHwYDVR0jBBgwFoAUA1vI26YMj3njkfCU"
            +"IXbo244kLjkwVwYDVR0SBFAwToZMbGRhcDovL3Brc2xkYXAudHR0Yy5kZS9vdT1U"
            +"LVRlbGVTZWMgVGVzdCBESVIgODpQTixvPURldXRzY2hlIFRlbGVrb20gQUcsYz1k"
            +"ZTAKBgYrJAMDAQIFAAOBgQArj4eMlbAwuA2aS5O4UUUHQMKKdK/dtZi60+LJMiMY"
            +"ojrMIf4+ZCkgm1Ca0Cd5T15MJxVHhh167Ehn/Hd48pdnAP6Dfz/6LeqkIHGWMHR+"
            +"z6TXpwWB+P4BdUec1ztz04LypsznrHcLRa91ixg9TZCb1MrOG+InNhleRs1ImXk8"
            +"MQ==");

    private static String ldapURL1 = "ldap://pksldap.tttc.de:389";
    private static String[] certAttrs1 = {"userCertificate", "cACertificate"};
    private static List certAttrList1 = Arrays.asList(certAttrs1);
    private static String[] cRLAttrs1 = {"certificateRevocationList"};
    private static List crlAttrList1 = Arrays.asList(cRLAttrs1);
    private static String ldapCertAttr1 = "cn";
    private static String certSubjectAttr1 = "cn";
    private static String ldapCRLAttr1 = "o";
    private static String cRLIssuerAttr1 = "o";
    private static String searchForSerialNumberIn1 = "cn";
    
    private static X509LDAPCertStoreParameters params1 = new X509LDAPCertStoreParameters(ldapURL1, null,
            certAttrList1, crlAttrList1, ldapCertAttr1, certSubjectAttr1, ldapCRLAttr1, cRLIssuerAttr1, searchForSerialNumberIn1);

// TODO: generalise this using a property or something!
    private static String ldapURL2 = "ldap://directory.d-trust.de:389";
    private static String[] certAttrs2 = {"userCertificate", "cACertificate"};
    private static List certAttrList2 = Arrays.asList(certAttrs2);
    private static String[] cRLAttrs2 = {"certificateRevocationList"};
    private static List crlAttrList2 = Arrays.asList(cRLAttrs2);
    private static String ldapCertAttr2 = "cn";
    private static String certSubjectAttr2 = "cn";
    private static String ldapCRLAttr2 = "o";
    private static String cRLIssuerAttr2 = "o";
    private static String searchForSerialNumberIn2 = "uid";
    
    private static X509LDAPCertStoreParameters params2 = new X509LDAPCertStoreParameters(ldapURL2, null,
            certAttrList2, crlAttrList2, ldapCertAttr2, certSubjectAttr2, ldapCRLAttr2, cRLIssuerAttr2, searchForSerialNumberIn2);

    private byte[] cert2 = Base64.decode(
            "MIIEADCCAuigAwIBAgIDAJ/QMA0GCSqGSIb3DQEBBQUAMD8xCzAJBgNVBAYTAkRF"
            +"MRUwEwYDVQQKDAxELVRydXN0IEdtYkgxGTAXBgNVBAMMEEQtVFJVU1QgRGVtbyBD"
            +"QTEwHhcNMDYwMzAyMTYxNTU3WhcNMDgwMzEyMTYxNTU3WjB+MQswCQYDVQQGEwJE"
            +"RTEUMBIGA1UECgwLTXVzdGVyIEdtYkgxFzAVBgNVBAMMDk1heCBNdXN0ZXJtYW5u"
            +"MRMwEQYDVQQEDApNdXN0ZXJtYW5uMQwwCgYDVQQqDANNYXgxHTAbBgNVBAUTFERU"
            +"UldFMTQxMjk5NDU1MTgwMTIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC"
            +"AQEAjLDFeviSZDEZgLzTdptU4biPgNV7SvLqsNholfqkyQm2r5WSghGZSjhKYIne"
            +"qKmZ08W59a51bGqDEsifYR7Tw9JC/AhH19fyK01+1ZAXHalgVthaRtLw31lcoTVJ"
            +"R7j9fvrnW0sMPVP4m5gePb3P5/pYHVmN1MjdPIm38us5aJOytOO5Li2IwQIG0t4M"
            +"bEC6/1horBR5TgRl7ACamrdaPHOvO1QVweOqYU7uVxLgDTK4mSV6heyrisFMfkbj"
            +"7jT/c44kXM7dtgNcmESINudu6bnqaB1CxOFTJ/Jzv81R5lf7pBX2LOG1Bu94Yw2x"
            +"cHUVROs2UWY8kQrNUozsBHzQ0QIDAKq5o4HFMIHCMBMGA1UdIwQMMAqACEITKrPL"
            +"WuYiMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZC10"
            +"cnVzdC5uZXQwEAYDVR0gBAkwBzAFBgMqAwQwEQYDVR0OBAoECEvE8bXFHkFLMA4G"
            +"A1UdDwEB/wQEAwIGQDAPBgUrJAgDCAQGDARUZXN0MB8GA1UdEQQYMBaBFG0ubXVz"
            +"dGVybWFubkB0ZXN0LmRlMA8GBSskCAMPBAYMBFRlc3QwDQYJKoZIhvcNAQEFBQAD"
            +"ggEBADD/X+UZZN30nCBDzJ7MtmgwvMBVDAU6HkPlzfyn9pxIKFrq3uR9wcY2pedM"
            +"yQQk0NpTDCIhAYIjAHysMue0ViQnW5qq8uUCFn0+fsgMqqTQNRmE4NIqUrnYO40g"
            +"WjcepCEApkTqGf3RFaDMf9zpRvj9qUx18De+V0GC22uD2vPKpqRcvS2dSw6pHBW2"
            +"NwEU+RgNhoPXrHt332PEYdwO0zOL7eSLBD9AmkpP2uDjpMQ02Lu9kXG6OOfanwfS"
            +"jHioCvDXyl5pwSHwrHNWQRb5dLF12Fg41LMapDwR7awAKE9h6qHBonvCMBPMvqrr"
            +"NktqQcoQkluR9MItONJI5XHADtU=");
    
    public void performTest()
        throws Exception
    {
        CertStore cs = CertStore.getInstance("X509LDAP", params1, "BC");
        X509CertSelector sl = new X509CertSelector();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate xcert = (X509Certificate) cf
                .generateCertificate(new ByteArrayInputStream(cert1));
        sl.setCertificate(xcert);
        Collection coll = cs.getCertificates(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("certificate could not be picked from LDAP directory.");
        }
        sl.setCertificate(null);
        sl.setSubject(xcert.getSubjectX500Principal().getEncoded());
        coll = cs.getCertificates(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("certificate could not be picked from LDAP directory.");
        }
        X509CRLSelector sl2 = new X509CRLSelector();
//        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(directCRL));
//        sl2.addIssuer(crl.getIssuerX500Principal());
        coll = cs.getCRLs(sl2);
        if (!coll.iterator().hasNext())
        {
            fail("CRL could not be picked from LDAP directory.");
        }
        cs = CertStore.getInstance("X509LDAP", params2, "BC");
        sl = new X509CertSelector();
        xcert = (X509Certificate) cf
                .generateCertificate(new ByteArrayInputStream(cert2));
        sl.setCertificate(xcert);
        coll = cs.getCertificates(sl);
        if (coll.isEmpty() || !coll.iterator().next().equals(xcert))
        {
            fail("certificate could not be picked from LDAP directory.");
        }
    }

    public String getName()
    {
        return "LDAPCertStoreTest";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new X509LDAPCertStoreTest());
    }
}
