package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERSequence;

import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

public class PKCS12Test
    implements Test
{
    byte[] pkcs12 = Base64.decode(
              "MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA1wwgDCABgkqhkiG9w0BBwGggCSABIID"
            + "RDCCA0AwggM8BgsqhkiG9w0BDAoBAqCCArEwggKtMCcGCiqGSIb3DQEMAQMwGQQU"
            + "FlnNVpQoEHc+J3UEGxARipkHu5kCAWQEggKAAH9tmy40lly6QDoc1TfmY9y2qysD"
            + "+lrgk+dnxP04RfoJfycTRDeaz2sPLImZtio9nsqCFqtzU/sleWigbH34BpKU1sC0"
            + "Gq1cyik0GO65sW95S6YjKtGcGOBfQCPk1oQjfiqnfU3GoeOaG3COQJukMFj8unv5"
            + "5u0xbX1hwO8SsZmr9RjPzLrVaeY6BP5+CCzOKBajGxneIDqnQW7/kBIVWK7M+JXG"
            + "dgQyiKhD6NvXL/zD8oKEne0nIX7IokQuWEn68Sglv5OSclsSdvHTk57bCuV5lVzo"
            + "IzczA4J/LZWdrtITeVefBLQSalBzpRderSTMj485z2x5ChizhjE627/KQ5vkKQkQ"
            + "VqXYYXVyeTvKZRpL7vz13C4DUCwNim1XvNSCNebXS1yHJRtcONDhGJN3UsrVjHr+"
            + "2kCfE5SCEeSU/dqgNLuLa1tk5+jwZFNj/HjO88wlOwPCol1uuJjDpaEW7dxu5qsV"
            + "SfZhEXWHs8rZAMttFMziyxsEkZe8kqngRbNJOY6KpppYedsMWDusUJGfIHo+8zym"
            + "iw3gv/z+lmFOlDGtCKMk9Es/MgfjpbfhbTVYHOBKS6Qyrz7LdTuBMI8XdsZMuN+U"
            + "f73690ggLmKWIELUg8h1RX0ra2n6jOc/1rnebAifMhiMkL1ABQvqOobfOrG/9h9X"
            + "cXoi64Qrhtc3T7yMAHafBX5KUcNkbcn6kssYhpvd8bPADoLBnbx3GxGh/uziB0zK"
            + "QEI0GnaY4SL7aR4C5xNNi41lYtsR6ohKyfPEGslhrhd4axx0cKxC2sHgVl0k+r8B"
            + "8Vu44XHbW8LqdspjOHN9qg2erES1Dvgj05SfHDup+V6a3ogJo2YKXOiu3DF4MFEG"
            + "CSqGSIb3DQEJFDFEHkIARABhAHYAaQBkACAARwAuACAASABvAG8AawAnAHMAIABW"
            + "AGUAcgBpAFMAaQBnAG4ALAAgAEkAbgBjAC4AIABJAEQwIwYJKoZIhvcNAQkVMRYE"
            + "FKEcMJ798oZLFkH0OnpbUBnrTLgWAAQBAAQBAAQBAAQBAASCDLIAMIAGCSqGSIb3"
            + "DQEHBqCAMIACAQAwgAYJKoZIhvcNAQcBMCcGCiqGSIb3DQEMAQYwGQQUTErHkWZ8"
            + "nBXZYWO53FH4yqRZZsECAWSggASCDGCreuCr6/azcOv5w04bN3jkg4G2dsvTPAjL"
            + "8bichaEOQCykhuNPt1dv3FsjUsdFC550K0+Y48RylOI30aMr5rlos9peBNF1jvhO"
            + "ih/WFi1ngMhxXKrbkt7NVAeh7/76kCASlaOodPFUMi9gUCBPagMH7a+R5czrVec1"
            + "Y6PAJjelemT9UaPI3hRKQPtD9jq0+NA7LC9ATtwBvXPraT2IyJrtiT+qaH7Mm7hJ"
            + "Kd6jT9Est0xk6UZm/z0xF6xUbTfxMLwxMD1R/7ANFxLbR3tcNtNoECCO7xOkUjDn"
            + "+VsOLR95RWWTov6ORPWS1pNzU/C3GfumxcwVbocBYHh7E6LT3b3tH0EI5Bfq9x60"
            + "r+ID/eMgLo25N2LNih/QNZ610bKFoiQyIScRFgTe6cmhwfh+rnzlHDqYT4Fiyw9U"
            + "+RVZlkicXeXr1sp267GxC36lwCmAFWxOOxT7UU6JTG5bbBYqLvRFxCms+/kR/UDk"
            + "VE3E8Wn7sjMs2UTioKjC8Lo1Ol65HDdoaxdJ+oeZJ12se6A0+aCE2AbmW/UR/sDw"
            + "xS7Knx/KMCDEIOTgelvw8IcaPm3/8WvoJ3QzKAkwgVCa/iRR3YtUfFD0D1YU0KpP"
            + "P+cF75lEsks2CFO/qAamMYmIGddi/pKh3Z+z7knYYi97Hipt2HqDNkhTZhMDCmPo"
            + "BxrdKMBfz6bwBe3ZILdnpPn6bxLHKI2nY/nXWlpX9Nkq0tZdAYp4RfUleFCRozpD"
            + "lb8iFKALz+CmmTWBsitoGqtbxsScYGcLTfCLQ6czPeiEzgJUfJpbd1Cq5Pb67oXx"
            + "V4ZcBgdTTbY2Suk+X9WV800QDKKxTb6gmqk9mSovoWwNYXeToWraNcEsv79rRYDz"
            + "aMimCM15fN79yCge1TTbdX0T1By77mc8Fh0JNHixHG8csA2KLRbyU++29Tlc7VSw"
            + "SMcN8ovgTVuEbMalv85TnKD/3wQ33mv/F0Uvkb5dXId5HRS2RwEi6/IF2GTCimsK"
            + "ORyAtl7wU8gE3DzgdF7th7p/aANb8Xm56PqsF6ElLVUW8KENfORqMaYrjQZzYA9L"
            + "X/W9mo+7rymiWDD11Pzit6bfo8sQ6rgq5TufhATSDtNhHYbz7gU2BBOOOD+rDeVf"
            + "6yPrIufWVi3V05W+SIzyLy11mD/ekIooBbW5Xtpqy2UHFVKQV+fUGsVNzagUaROu"
            + "VSD3Rr6lqs58YdN8OJodfyi4SDrd+TT5d2IUJqteyoc08NumZYsrDxMCZ16d4aKn"
            + "JJye0kmThqPL6NE5AGAZ7Deh86Z+SqagkU3BS8o5c3a5xWItmCx0r/tiBXU5HuiJ"
            + "OHySdA0+Td3l9FhIwV/0YlONBFXLYIt0gIBXO+tRd/2TuaJZiSMinb8cYPuk4fTX"
            + "yxf0yul8kqq908U6yxmIV3QjYVRuB7b509F6GmxIrq05vBDz6cOujSpivx9ZEC9I"
            + "RLXSGsz8Xy5pv2VA6JMGu3eGxNwcBYdMHkHxLzMybumORO4q9jKg9912hjDhsrNZ"
            + "7LdUjz8gwVqTlg/cOzYN8lNSVc6hVrlV2lw2G355RuwBnryheT2DWY/0SEAQX+V5"
            + "XvYU3XPQrcT5K7CcAPA3gMCpdliH21xswGC0p16GFHKE5Fp/zvNQZVBYAF7/NIC3"
            + "vDVKx+24bJ8hmj2Pedzcg5PCFlGK7J/7F78U8uQdP+/1hjIdwkmay196e03BWMga"
            + "y+kkWrOKva63MLoQatLVFG24Fovdp4WZeGzhpse3oR58LlCHdh1l8lRqAak6Hnv9"
            + "hOD2RcUmcCgmOnWobMBauUBg60Cjdv6qTi2XCYm+kr0hshGZdqaq9JapO7VT8wZD"
            + "f+Lj9Kq3G2Qg2xluiF8Lt0RjEXoao/xxCXLPdpWSn1a5P1NO1zAQIkB6lfpC8O5E"
            + "rRAkfzBiRtXNMYaqga39Fu+Pi6SYr/0PYhTXVm17xP3AJBu/jk1AAXdpCPPLgON0"
            + "9FKEbjzouSpy7g9wBvuyLshsj+vV53HeLtLKzINn5w4iy2VMur1pscERbEjAhH0D"
            + "S7WWoILpKDyIoUL2195kEvYs8C7Og/PVrRHGeeg1WyJVKlIp5zSrE/L1tQ2aORTC"
            + "ZFMQeuumCD1ZpEG2yThFFPPXWYORsNKIOq5+IqxK+MRxXcfku4qiV4c7PUx4P/Xu"
            + "P5PCkNd+s+ywCzqg6KJHEnQc1uh/HEk47OKikMjYprCwfdJhLiBAKc4bHgGixZfp"
            + "IDkRib/9mvrqLpGXITLCffDFaLBD0taAVyZdpvQLIZFnzjdhg3iWrYHMOgsgtZks"
            + "fvhoOtNmSlGWVGlsZM9UsM04954YiXvkmbHX8YbKIzau838aoGP0auwcL6YVN0rY"
            + "58b5AeK05G5m4hjgTnL0xYOMjrUBkXIn5Nv1x/24GIj6kK2El6Tt1kQEldNOUWkh"
            + "rn3KU7Y92JRxnvBVIGXw7X4hns4TRE/Sjt/0NIt+GxhKaCG//bjlh+GR1CyJX3Up"
            + "tcp1edJxOJiU13HKxegRPNCmSORlhoal3XzxWh0ytUttPlwsO20SQhnosFcbxnwf"
            + "gtEmeJ3basdeuXShuScBbpHMoIiGTen6IdPz4cM5hcZj7Wbj0LfXbbiEN+WOz0g7"
            + "MiB9jrdB4dGCDffZRyep/R6Jko6cHIA1xrLBLnr26c9u7vzCP1IauBn8dJOURdKX"
            + "EWLZNXWEseOGvvFoKmSxfA1Dbco0hPx/D+Yhmurajpe5DcnnhJH6E7SrLWrBhcC+"
            + "EMcbrOBgu63qclYuyCaopiqKQJ2IqUHvoIEuD//sZooDx0JeoFRO5VakkTO6WHd8"
            + "JpOOEU2f6Zjg++HdIl0QK7xcUaRH075LzEfqgn1vyw6JN6ex8D76sf/nAy01NvDP"
            + "ij48Z50XDwXu4kJGJvv0AJwId8BpjziBF0j3K/DIYOOpd6nW4EvdivCgaCnxqlIU"
            + "/u1OP4BwpO+AUjJh6RKlKviGihQpi103DFhRyXNDhh55pqgCCCuNeEB+ovRt7Uxz"
            + "lGAVRSxJh1Zbjp/+iQun0E32RlSR4Dizp5vDk8NBZpIiKRqI+8GWZc3G1igp7dvV"
            + "iTLw4OdWMKwhccV5+3Ll/W72aNVmazYUoYOVn+OYS1NJkER0tjFOCozRGm5hfkxG"
            + "lP+02wbH5uu/AQoJMqWIxT6l46IWC24lmAnDCXuM+gWmwUvyXLwuBdejVK8iG1Ln"
            + "fg1qztoLpYRbBROgRdpt2cbPRm+9seqrth3eJbtmxCvuh3bZ3pR2e0/r5Tob/fDc"
            + "Oc5Kp+j4ndXWkwpaOuH1yxam7zNJR+mcYp1Wiujia5qIeY1QCAEY5QgAWaSHtjlE"
            + "prwUuootA2XmV7D8Vsr9BValhm9zMKj6IzsPmM+HZJWlhHcoucuAmPK6Lnys3Kv/"
            + "mbkSgNOqfJDY901veFfKeqiCbAm6hZjNWoQDNJKFhjXUALrcOv9VCFPA3bMW3Xul"
            + "/sB4Mq595e+x/1HkNOgZorBv97C6X7ENVDaAFcyZvrRU/ZeDnvFhisfxS4EJhzxl"
            + "cWWnQhzD+ur1FTTlkmUFzgoB/rW+i3XigiHOuRRnkcoMy1uV17rwH8eELHJuYni5"
            + "vu2QUaD4jNEhliE2XCsn8Sm6bcXnfzBa7FXC39QvAcdJHzqcD6iIwjIzhKLu+/Xo"
            + "WFMFFNsgV78AwzPAn6TRya8LLCYPoIZkEP4qBoeZtUZ8PIS/Y7M9QStMwa/NI9SP"
            + "swb3iScTGvor/obUEQS4QM6mVxFMpQWfwJfyU6jingX4EHREmqvZ3ehzU8ZLOdKz"
            + "RKuk022YDT7hwEQ+VL0Fg0Ld9oexqT96nQpUTHZtDRMViTuJoUYTneDs2c9tsY4m"
            + "WBqamZQSfTegj4sLMZagkuSUp/SpPM2zSGuD3nY6u3553gIM9jYhvLBEXwjGudVC"
            + "wMd3bqo/4EhnKb2PcwUzdaMkipQlNteHZjBT1ici63xjJva+di0qTV+W9cyYyHwg"
            + "1927X2qcMh06BhbHlcXQKbgmbL18KJEtK+GGhGNkP7mtPyHHgBb6vref/z8p7oxT"
            + "2CG+oBuN/z+xQoYfe9c4IC3e/kNNDIoyYvPyEzAdfMS2aL8qDxzc5GH9UE9kcusJ"
            + "/2dNEFTzhitQiLS9yAAr/y8F9UpCNMO6CEEy9duwkp7k61FJLyf/qzmEnEEzA/57"
            + "WT3S3btn37M4N0s4TRC4KIyvLLNTgZa7lkR8P3z+9+jcfDDbLjr1zJzvJa7s/rsr"
            + "hIRdwS7/eqE3IF1R3VoT5jqKjXQUHUYABAEABAEABAEABAEABAEABAEABAEABAEA"
            + "BAEABAEABAEAAAAAAAAAMDwwITAJBgUrDgMCGgUABBQkxmfswQq/i9b/6+gJXIcF"
            + "roHQQwQUk7Mf8ESNG002xlaWj/gvzjRoTmsCAWQAAA==");
    
    private boolean isSameAs(
            byte[]  a,
            byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }
        
        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        
        return true;
    }
    
    public TestResult perform()
    {
        try
        {
            ASN1InputStream     aIn = new ASN1InputStream(new ByteArrayInputStream(pkcs12));
            ASN1Sequence        obj = (ASN1Sequence)aIn.readObject();
            Pfx                 bag = new Pfx(obj);
            ContentInfo         info = bag.getAuthSafe();
            MacData             mData = bag.getMacData();
            DigestInfo          dInfo = mData.getMac();
            AlgorithmIdentifier algId = dInfo.getAlgorithmId();
            byte[]              salt = mData.getSalt();
            int                 itCount = mData.getIterationCount().intValue();

            aIn = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString)info.getContent()).getOctets()));

            AuthenticatedSafe   authSafe = new AuthenticatedSafe((ASN1Sequence)aIn.readObject());
            ContentInfo[]       c = authSafe.getContentInfo();

            //
            // private key section
            //
            if (!c[0].getContentType().equals(PKCSObjectIdentifiers.data))
            {
                return new SimpleTestResult(false, getName() + ": failed comparison data test");
            }
            
            aIn = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString)c[0].getContent()).getOctets()));
            ASN1Sequence    seq = (ASN1Sequence)aIn.readObject();
            
            SafeBag b = new SafeBag((ASN1Sequence)seq.getObjectAt(0));
            if (!b.getBagId().equals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag))
            {
                return new SimpleTestResult(false, getName() + ": failed comparison shroudedKeyBag test");
            }
            
            EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfo.getInstance((ASN1Sequence)b.getBagValue());
            
            encInfo = new EncryptedPrivateKeyInfo(encInfo.getEncryptionAlgorithm(), encInfo.getEncryptedData());
            
            b = new SafeBag(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, encInfo.toASN1Object(), b.getBagAttributes());
            
            ByteArrayOutputStream abOut = new ByteArrayOutputStream();
            ASN1OutputStream      berOut = new ASN1OutputStream(abOut);
            
            berOut.writeObject(new DERSequence(b));
            
            c[0] = new ContentInfo(PKCSObjectIdentifiers.data, new BERConstructedOctetString(abOut.toByteArray()));
            
            //
            // certificates
            //
            if (!c[1].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                return new SimpleTestResult(false, getName() + ": failed comparison encryptedData test");
            }
            
            EncryptedData   eData = EncryptedData.getInstance(c[1].getContent());
            
            c[1] = new ContentInfo(PKCSObjectIdentifiers.encryptedData, eData);
            
            //
            // create an octet stream represent the BER encoding of authSafe
            //
            authSafe = new AuthenticatedSafe(c);
            
            abOut = new ByteArrayOutputStream();
            berOut = new ASN1OutputStream(abOut);

            berOut.writeObject(authSafe);
            
            info = new ContentInfo(PKCSObjectIdentifiers.data, new BERConstructedOctetString(abOut.toByteArray()));
            
            mData = new MacData(new DigestInfo(algId, dInfo.getDigest()), salt, itCount);
            
            bag = new Pfx(info, mData);

            //
            // comparison test
            //
            
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
            
            aOut.writeObject(bag);
            
            if (!isSameAs(bOut.toByteArray(), pkcs12))
            {
                return new SimpleTestResult(false, getName() + ": failed comparison test");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString(), e);
        }
    }

    public String getName()
    {
        return "PKCS12";
    }

    public static void main(
        String[] args)
    {
        PKCS12Test    test = new PKCS12Test();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
