package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.jce.PKCS7SignedData;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 **/
public class PKCS7SignedDataTest
    implements Test
{
    byte[] sample1 = Base64.decode(
          "MIINBwYJKoZIhvcNAQcCoIIM+DCCDPQCAQExDjAMBggqhkiG9w0CBQUAMAsG"
        + "CSqGSIb3DQEHAaCCC0EwggNiMIICy6ADAgECAhAL2gsXwT+JjqsJdHq0zi4z"
        + "MA0GCSqGSIb3DQEBAgUAMF8xCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJp"
        + "U2lnbiwgSW5jLjE3MDUGA1UECxMuQ2xhc3MgMSBQdWJsaWMgUHJpbWFyeSBD"
        + "ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw05ODA1MTIwMDAwMDBaFw0wODA1"
        + "MTIyMzU5NTlaMIHMMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0GA1UE"
        + "CxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazFGMEQGA1UECxM9d3d3LnZlcmlz"
        + "aWduLmNvbS9yZXBvc2l0b3J5L1JQQSBJbmNvcnAuIEJ5IFJlZi4sTElBQi5M"
        + "VEQoYyk5ODFIMEYGA1UEAxM/VmVyaVNpZ24gQ2xhc3MgMSBDQSBJbmRpdmlk"
        + "dWFsIFN1YnNjcmliZXItUGVyc29uYSBOb3QgVmFsaWRhdGVkMIGfMA0GCSqG"
        + "SIb3DQEBAQUAA4GNADCBiQKBgQC7WkSKBBa7Vf0DeootlE8VeDa4DUqyb5xU"
        + "v7zodyqdufBou5XZMUFweoFLuUgTVi3HCOGEQqvAopKrRFyqQvCCDgLpL/vC"
        + "O7u+yScKXbawNkIztW5UiE+HSr8Z2vkV6A+HthzjzMaajn9qJJLj/OBluqex"
        + "fu/J2zdqyErICQbkmQIDAQABo4GwMIGtMA8GA1UdEwQIMAYBAf8CAQAwRwYD"
        + "VR0gBEAwPjA8BgtghkgBhvhFAQcBATAtMCsGCCsGAQUFBwIBFh93d3cudmVy"
        + "aXNpZ24uY29tL3JlcG9zaXRvcnkvUlBBMDEGA1UdHwQqMCgwJqAkoCKGIGh0"
        + "dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTEuY3JsMAsGA1UdDwQEAwIBBjAR"
        + "BglghkgBhvhCAQEEBAMCAQYwDQYJKoZIhvcNAQECBQADgYEAAn2eb0VLOKC4"
        + "3ulTZCG85Ewrjx7+kkCs2Ao5aqEyISwHm6tZ/tJiGn1VOLA3c9z0B2ZjYr3h"
        + "U3BSh+eo2FLpWy2q4d7PrDFU1IsZyNgjqO8EKzJ9LBgcyHyJqC538kTRZQpN"
        + "dLXu0xuSc3QuiTs1E3LnQDGa07LEq+dWvovj+xUwggNmMIICz6ADAgECAhAN"
        + "i0/uqtIYW/R1ap0p4X/7MA0GCSqGSIb3DQEBAgUAMF8xCzAJBgNVBAYTAlVT"
        + "MRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjE3MDUGA1UECxMuQ2xhc3MgMSBQ"
        + "dWJsaWMgUHJpbWFyeSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw05ODA1"
        + "MTIwMDAwMDBaFw0wODA1MTIyMzU5NTlaMIHMMRcwFQYDVQQKEw5WZXJpU2ln"
        + "biwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazFGMEQG"
        + "A1UECxM9d3d3LnZlcmlzaWduLmNvbS9yZXBvc2l0b3J5L1JQQSBJbmNvcnAu"
        + "IEJ5IFJlZi4sTElBQi5MVEQoYyk5ODFIMEYGA1UEAxM/VmVyaVNpZ24gQ2xh"
        + "c3MgMSBDQSBJbmRpdmlkdWFsIFN1YnNjcmliZXItUGVyc29uYSBOb3QgVmFs"
        + "aWRhdGVkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7WkSKBBa7Vf0D"
        + "eootlE8VeDa4DUqyb5xUv7zodyqdufBou5XZMUFweoFLuUgTVi3HCOGEQqvA"
        + "opKrRFyqQvCCDgLpL/vCO7u+yScKXbawNkIztW5UiE+HSr8Z2vkV6A+Hthzj"
        + "zMaajn9qJJLj/OBluqexfu/J2zdqyErICQbkmQIDAQABo4G0MIGxMBEGCWCG"
        + "SAGG+EIBAQQEAwIBBjA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLnZl"
        + "cmlzaWduLmNvbS9wY2ExLjEuMS5jcmwwRwYDVR0gBEAwPjA8BgtghkgBhvhF"
        + "AQcBATAtMCsGCCsGAQUFBwIBFh93d3cudmVyaXNpZ24uY29tL3JlcG9zaXRv"
        + "cnkvUlBBMA8GA1UdEwQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMA0GCSqGSIb3"
        + "DQEBAgUAA4GBAEJ8Dt+MeUysvwjsTVUvUImgxV5OLl6VMpt5rWURCxxKUsTV"
        + "qDEhjt4Qm2wIxQfmA7nnyDR4CQnyvAZC+FqMg9GK3qoi9dnjIdLPZYwGM7DN"
        + "ILIzzQq9PuGdwTWpZLCnpSRb6fFo6xPEfDf0lGQNmsW9MxfvgzOgPuWqPq7Y"
        + "cx+tMIIEbTCCA9agAwIBAgIQLhd1a93UopTSLMdWFx6E0jANBgkqhkiG9w0B"
        + "AQQFADCBzDEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZl"
        + "cmlTaWduIFRydXN0IE5ldHdvcmsxRjBEBgNVBAsTPXd3dy52ZXJpc2lnbi5j"
        + "b20vcmVwb3NpdG9yeS9SUEEgSW5jb3JwLiBCeSBSZWYuLExJQUIuTFREKGMp"
        + "OTgxSDBGBgNVBAMTP1ZlcmlTaWduIENsYXNzIDEgQ0EgSW5kaXZpZHVhbCBT"
        + "dWJzY3JpYmVyLVBlcnNvbmEgTm90IFZhbGlkYXRlZDAeFw0wMTEyMTcwMDAw"
        + "MDBaFw0wMjAyMTUyMzU5NTlaMIIBETEXMBUGA1UEChMOVmVyaVNpZ24sIElu"
        + "Yy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxRjBEBgNVBAsT"
        + "PXd3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9yeS9SUEEgSW5jb3JwLiBieSBS"
        + "ZWYuLExJQUIuTFREKGMpOTgxHjAcBgNVBAsTFVBlcnNvbmEgTm90IFZhbGlk"
        + "YXRlZDEnMCUGA1UECxMeRGlnaXRhbCBJRCBDbGFzcyAxIC0gTWljcm9zb2Z0"
        + "MRYwFAYDVQQDFA1NaWtlIEJyZW1mb3JkMSwwKgYJKoZIhvcNAQkBFh12ZXJp"
        + "c2lnbnRlc3RAYmlnLmZhY2VsZXNzLm9yZzCBnzANBgkqhkiG9w0BAQEFAAOB"
        + "jQAwgYkCgYEA0rFDQ+HxY86Yfr0wYCZQGu6VqI/4lLtu0kwiAsHY1rRszK1H"
        + "TJd54TTpyLOv8jYNWU6c5dowB7FzCMLJ/I8E/RUPqqvIcV1HY0ijm0odsCzk"
        + "oKd/zKsECUEYYEy+aWscexAbVBpc0tU8KczxbaaApOKDUlC9eGBtAhTkvkXJ"
        + "s48CAwEAAaOCAQYwggECMAkGA1UdEwQCMAAwgawGA1UdIASBpDCBoTCBngYL"
        + "YIZIAYb4RQEHAQEwgY4wKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LnZlcmlz"
        + "aWduLmNvbS9DUFMwYgYIKwYBBQUHAgIwVjAVFg5WZXJpU2lnbiwgSW5jLjAD"
        + "AgEBGj1WZXJpU2lnbidzIENQUyBpbmNvcnAuIGJ5IHJlZmVyZW5jZSBsaWFi"
        + "LiBsdGQuIChjKTk3IFZlcmlTaWduMBEGCWCGSAGG+EIBAQQEAwIHgDAzBgNV"
        + "HR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLnZlcmlzaWduLmNvbS9jbGFzczEu"
        + "Y3JsMA0GCSqGSIb3DQEBBAUAA4GBAFCIm9xpgS9C64+B0hxEXDvJkYyBSwhd"
        + "DT/650jbPHrdF7Bego3RozqNPSsP0DkYMJ8K4MAfAGnQ8u9+zx2pS4XxYm91"
        + "j77Z7eqTW9dDraZc9r16r/RzxGV12+Bu8L++T+JyCAbGXnQrEYccTV+Pql46"
        + "bJWSVkeCwtnxxZ0YIRTxMYIBizCCAYcCAQEwgeEwgcwxFzAVBgNVBAoTDlZl"
        + "cmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3Jr"
        + "MUYwRAYDVQQLEz13d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvUlBBIElu"
        + "Y29ycC4gQnkgUmVmLixMSUFCLkxURChjKTk4MUgwRgYDVQQDEz9WZXJpU2ln"
        + "biBDbGFzcyAxIENBIEluZGl2aWR1YWwgU3Vic2NyaWJlci1QZXJzb25hIE5v"
        + "dCBWYWxpZGF0ZWQCEC4XdWvd1KKU0izHVhcehNIwDAYIKoZIhvcNAgUFADAN"
        + "BgkqhkiG9w0BAQEFAASBgAc1aYCUgUnXxRK5RfArNuu6FBQkEg4wZdOxHn+q"
        + "UQpMZE1ON+9Z/H5p922XoM557EXU4YAdcsGqCXv4TqOXf2jMCZrBuAkaOXC2"
        + "xiRdYihm2hPE7mi7NBTVmoUnstvkO+G5yOoNm41Ev1PyH6ijCKIWwjQYlYuG"
        + "YGBH6F9KCk+sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    byte[] sample2 = Base64.decode(
          "MIIIlAYJKoZIhvcNAQcCoIIIhTCCCIECAQExCzAJBgUrDgMCGgUAMAsGCSqG"
        + "SIb3DQEHAaCCB3UwggOtMIIDa6ADAgECAgEzMAsGByqGSM44BAMFADCBkDEL"
        + "MAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlQYWxvIEFsdG8x"
        + "HTAbBgNVBAoTFFN1biBNaWNyb3N5c3RlbXMgSW5jMSMwIQYDVQQLExpKYXZh"
        + "IFNvZnR3YXJlIENvZGUgU2lnbmluZzEcMBoGA1UEAxMTSkNFIENvZGUgU2ln"
        + "bmluZyBDQTAeFw0wMTA1MjkxNjQ3MTFaFw0wNjA1MjgxNjQ3MTFaMG4xHTAb"
        + "BgNVBAoTFFN1biBNaWNyb3N5c3RlbXMgSW5jMSMwIQYDVQQLExpKYXZhIFNv"
        + "ZnR3YXJlIENvZGUgU2lnbmluZzEoMCYGA1UEAxMfVGhlIExlZ2lvbiBvZiB0"
        + "aGUgQm91bmN5IENhc3RsZTCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQD9f1OB"
        + "HXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9jVj6v8X1ujD2"
        + "y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX58aophUP"
        + "BPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8VIwvM"
        + "spK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlXTAs9"
        + "B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCj"
        + "rh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtV"
        + "JWQBTDv+z0kqA4GEAAKBgBWry/FCAZ6miyy39+ftsa+h9lxoL+JtV0MJcUyQ"
        + "E4VAhpAwWb8vyjba9AwOylYQTktHX5sAkFvjBiU0LOYDbFSTVZSHMRJgfjxB"
        + "SHtICjOEvr1BJrrOrdzqdxcOUge5n7El124BCrv91x5Ol8UTwtiO9LrRXF/d"
        + "SyK+RT5n1klRo3YwdDARBglghkgBhvhCAQEEBAMCAIcwDgYDVR0PAQH/BAQD"
        + "AgHGMB0GA1UdDgQWBBQwMY4NRcco1AO3w1YsokfDLVseEjAPBgNVHRMBAf8E"
        + "BTADAQH/MB8GA1UdIwQYMBaAFGXi9IbJ007wkU5Yomr12HhamsGmMAsGByqG"
        + "SM44BAMFAAMvADAsAhRmigTu6QV0sTfEkVljgij/hhdVfAIUQZvMxAnIHc30"
        + "y/u0C1T5UEG9glUwggPAMIIDfqADAgECAgEQMAsGByqGSM44BAMFADCBkDEL"
        + "MAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlQYWxvIEFsdG8x"
        + "HTAbBgNVBAoTFFN1biBNaWNyb3N5c3RlbXMgSW5jMSMwIQYDVQQLExpKYXZh"
        + "IFNvZnR3YXJlIENvZGUgU2lnbmluZzEcMBoGA1UEAxMTSkNFIENvZGUgU2ln"
        + "bmluZyBDQTAeFw0wMTA0MjUwNzAwMDBaFw0yMDA0MjUwNzAwMDBaMIGQMQsw"
        + "CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVBhbG8gQWx0bzEd"
        + "MBsGA1UEChMUU3VuIE1pY3Jvc3lzdGVtcyBJbmMxIzAhBgNVBAsTGkphdmEg"
        + "U29mdHdhcmUgQ29kZSBTaWduaW5nMRwwGgYDVQQDExNKQ0UgQ29kZSBTaWdu"
        + "aW5nIENBMIIBtzCCASwGByqGSM44BAEwggEfAoGBAOuvNwQeylEeaV2w8o/2"
        + "tUkfxqSZBdcpv3S3avUZ2B7kG/gKAZqY/3Cr4kpWhmxTs/zhyIGMMfDE87CL"
        + "5nAG7PdpaNuDTHIpiSk2F1w7SgegIAIqRpdRHXDICBgLzgxum3b3BePn+9Nh"
        + "eeFgmiSNBpWDPFEg4TDPOFeCphpyDc7TAhUAhCVF4bq5qWKreehbMLiJaxv/"
        + "e3UCgYEAq8l0e3Tv7kK1alNNO92QBnJokQ8LpCl2LlU71a5NZVx+KjoEpmem"
        + "0HGqpde34sFyDaTRqh6SVEwgAAmisAlBGTMAssNcrkL4sYvKfJbYEH83RFuq"
        + "zHjI13J2N2tAmahVZvqoAx6LShECactMuCUGHKB30sms0j3pChD6dnC3+9wD"
        + "gYQAAoGALQmYXKy4nMeZfu4gGSo0kPnXq6uu3WtylQ1m+O8nj0Sy7ShEx/6v"
        + "sKYnbwBnRYJbB6hWVjvSKVFhXmk51y50dxLPGUr1LcjLcmHETm/6R0M/FLv6"
        + "vBhmKMLZZot6LS/CYJJLFP5YPiF/aGK+bEhJ+aBLXoWdGRD5FUVRG3HU9wuj"
        + "ZjBkMBEGCWCGSAGG+EIBAQQEAwIABzAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud"
        + "IwQYMBaAFGXi9IbJ007wkU5Yomr12HhamsGmMB0GA1UdDgQWBBRl4vSGydNO"
        + "8JFOWKJq9dh4WprBpjALBgcqhkjOOAQDBQADLwAwLAIUKvfPPJdd+Xi2CNdB"
        + "tNkNRUzktJwCFEXNdWkOIfod1rMpsun3Mx0z/fxJMYHoMIHlAgEBMIGWMIGQ"
        + "MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVBhbG8gQWx0"
        + "bzEdMBsGA1UEChMUU3VuIE1pY3Jvc3lzdGVtcyBJbmMxIzAhBgNVBAsTGkph"
        + "dmEgU29mdHdhcmUgQ29kZSBTaWduaW5nMRwwGgYDVQQDExNKQ0UgQ29kZSBT"
        + "aWduaW5nIENBAgEzMAkGBSsOAwIaBQAwCwYHKoZIzjgEAQUABC8wLQIVAIGV"
        + "khm+kbV4a/+EP45PHcq0hIViAhR4M9os6IrJnoEDS3Y3l7O6zrSosA==");

    public String getName()
    {
        return "PKCS7SignedData";
    }

    public TestResult parseTest(
        byte[]  sample)
    {
        try
        {
            PKCS7SignedData signedData = new PKCS7SignedData(sample);

            Certificate[] certs = signedData.getCertificates();

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    /**
     * we generate a self signed certificate for the sake of testing - RSA -
     * and then try signing some data.
     */
    public TestResult checkCreation()
    {
        //
        // a sample key pair.
        //
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

        //
        // set up the keys
        //
        PrivateKey          privKey;
        PublicKey           pubKey;

        try
        {
            KeyFactory  fact = KeyFactory.getInstance("RSA", "BC");

            privKey = fact.generatePrivate(privKeySpec);
            pubKey = fact.generatePublic(pubKeySpec);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting up keys - " + e.toString());
        }

        //
        // distinguished name table.
        //
        Hashtable                   attrs = new Hashtable();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.ST, "Victoria");
        attrs.put(X509Principal.E, "feedback-crypto@bouncycastle.org");

        Vector                      ord = new Vector();
        Vector                      values = new Vector();

        ord.addElement(X509Principal.C);
        ord.addElement(X509Principal.O);
        ord.addElement(X509Principal.L);
        ord.addElement(X509Principal.ST);
        ord.addElement(X509Principal.E);

        values.addElement("AU");
        values.addElement("The Legion of the Bouncy Castle");
        values.addElement("Melbourne");
        values.addElement("Victoria");
        values.addElement("feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal(attrs));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal(attrs));
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("MD5WithRSAEncryption");

        try
        {
            X509Certificate cert = certGen.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream   sbIn = new ByteArrayInputStream(cert.getEncoded());
            ASN1InputStream        sdIn = new ASN1InputStream(sbIn);
            ByteArrayInputStream   bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory     fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            Certificate[]   certs = new Certificate[1];
            certs[0] = cert;

            PKCS7SignedData         pkcs7sd = new PKCS7SignedData(
                                            privKey, certs, "MD5");

            byte[]  bytes = Hex.decode("0102030405060708091011121314");

            pkcs7sd.update(bytes, 0, bytes.length);

            byte[]  p = pkcs7sd.getEncoded();

            pkcs7sd = new PKCS7SignedData(p);

            pkcs7sd.update(bytes, 0, bytes.length);

            if (!pkcs7sd.verify())
            {
                return new SimpleTestResult(false, "PKCS7 verification failed");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString());
        }

        //
        // create the certificate - version 1
        //
        X509V1CertificateGenerator  certGen1 = new X509V1CertificateGenerator();

        certGen1.setSerialNumber(BigInteger.valueOf(1));
        certGen1.setIssuerDN(new X509Principal(ord, attrs));
        certGen1.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen1.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen1.setSubjectDN(new X509Principal(ord, values));
        certGen1.setPublicKey(pubKey);
        certGen1.setSignatureAlgorithm("MD5WithRSAEncryption");

        try
        {
            X509Certificate cert = certGen1.generateX509Certificate(privKey);

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            // System.out.println(cert);
            if (!cert.getIssuerDN().equals(cert.getSubjectDN()))
            {
                return new SimpleTestResult(false, getName() + ": name comparison fails");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": error setting generating cert - " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }
    public TestResult perform()
    {
        TestResult  res = parseTest(sample1);

        if (!res.isSuccessful())
        {
            return res;
        }

        res = parseTest(sample2);
        if (!res.isSuccessful())
        {
            return res;
        }

        return checkCreation();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new PKCS7SignedDataTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
