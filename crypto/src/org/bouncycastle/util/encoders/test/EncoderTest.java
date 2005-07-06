package org.bouncycastle.util.encoders.test;

import java.util.*;
import org.bouncycastle.util.encoders.*;
import org.bouncycastle.util.test.*;

public class EncoderTest implements Test {

    /*
     *
     *  VARIABLES
     *
     */

    public static final boolean DEBUG = true;

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public static void main(String[] _args)
    {
        EncoderTest _test = new EncoderTest();
        System.out.println(_test.testBase64());
        System.out.println(_test.testHex());
    }

    public static void log(Exception _ex) {
        if(DEBUG) {
            _ex.printStackTrace();
        }
    }

    public static void log(String _msg) {
        if(DEBUG) {
            System.out.println(_msg);
        }
    }

    public String getName()
    {
        return "Encoder";
    }
    
    /*
     *
     *  TESTS
     *
     */

    public TestResult perform()
    {
        return testBase64();
    }
    
    
    public TestResult testBase64() {
        try {
            Random _r = new Random();
            
            byte[] _orig1024 = new byte[1024];
            _r.nextBytes(_orig1024);
            
            byte[] _orig2048 = new byte[2048];
            _r.nextBytes(_orig2048);
            
            byte[] _orig4096 = new byte[4096];
            _r.nextBytes(_orig4096);
            
            byte[] _orig8192 = new byte[8192];
            _r.nextBytes(_orig8192);
            
            byte[] _enc1024 = Base64.encode(_orig1024);
            byte[] _enc2048 = Base64.encode(_orig2048);
            byte[] _enc4096 = Base64.encode(_orig4096);
            byte[] _enc8192 = Base64.encode(_orig8192);
            
            byte[] _dec1024 = Base64.decode(_enc1024);
            byte[] _dec2048 = Base64.decode(_enc2048);
            byte[] _dec4096 = Base64.decode(_enc4096);
            byte[] _dec8192 = Base64.decode(_enc8192);
            
            if(!Arrays.equals(_orig1024, _dec1024)) {
                return new SimpleTestResult(false, "Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig2048, _dec2048)) {
                return new SimpleTestResult(false, "Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig4096, _dec4096)) {
                return new SimpleTestResult(false, "Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig8192, _dec8192)) {
                return new SimpleTestResult(false, "Failed Base64 test");
            }
            
            
            
            byte[] _orig1025 = new byte[1025];
            _r.nextBytes(_orig1025);
            
            byte[] _orig2049 = new byte[2049];
            _r.nextBytes(_orig2049);
            
            byte[] _orig4097 = new byte[4097];
            _r.nextBytes(_orig4097);
            
            byte[] _orig8193 = new byte[8193];
            _r.nextBytes(_orig8193);
            
            byte[] _enc1025 = Base64.encode(_orig1025);
            byte[] _enc2049 = Base64.encode(_orig2049);
            byte[] _enc4097 = Base64.encode(_orig4097);
            byte[] _enc8193 = Base64.encode(_orig8193);
            
            byte[] _dec1025 = Base64.decode(_enc1025);
            byte[] _dec2049 = Base64.decode(_enc2049);
            byte[] _dec4097 = Base64.decode(_enc4097);
            byte[] _dec8193 = Base64.decode(_enc8193);
            
            if(!Arrays.equals(_orig1025, _dec1025)) {
                return new SimpleTestResult(false, "Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig2049, _dec2049)) {
                return new SimpleTestResult(false, "Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig4097, _dec4097)) {
                return new SimpleTestResult(false, "Failed Base64 test");
            }
            
            if(!Arrays.equals(_orig8193, _dec8193)) {
                return new SimpleTestResult(false, "Failed Base64 test");
            }
            
            return new SimpleTestResult(true, "Passed Base64 test");
        }
        catch(Exception ex) {
            log(ex);
            return new SimpleTestResult(false, "Failed Base64 test");
        }
    }


    public TestResult testHex() {
        try {
            Random _r = new Random();
            
            byte[] _orig1024 = new byte[1024];
            _r.nextBytes(_orig1024);
            
            byte[] _orig2048 = new byte[2048];
            _r.nextBytes(_orig2048);
            
            byte[] _orig4096 = new byte[4096];
            _r.nextBytes(_orig4096);
            
            byte[] _orig8192 = new byte[8192];
            _r.nextBytes(_orig8192);
            
            byte[] _enc1024 = Hex.encode(_orig1024);
            byte[] _enc2048 = Hex.encode(_orig2048);
            byte[] _enc4096 = Hex.encode(_orig4096);
            byte[] _enc8192 = Hex.encode(_orig8192);
            
            byte[] _dec1024 = Hex.decode(_enc1024);
            byte[] _dec2048 = Hex.decode(_enc2048);
            byte[] _dec4096 = Hex.decode(_enc4096);
            byte[] _dec8192 = Hex.decode(_enc8192);
            
            if(!Arrays.equals(_orig1024, _dec1024)) {
                return new SimpleTestResult(false, "Failed Hex test");
            }
            
            if(!Arrays.equals(_orig2048, _dec2048)) {
                return new SimpleTestResult(false, "Failed Hex test");
            }
            
            if(!Arrays.equals(_orig4096, _dec4096)) {
                return new SimpleTestResult(false, "Failed Hex test");
            }
            
            if(!Arrays.equals(_orig8192, _dec8192)) {
                return new SimpleTestResult(false, "Failed Hex test");
            }
            
            
            byte[] _orig1025 = new byte[1025];
            _r.nextBytes(_orig1025);
            
            byte[] _orig2049 = new byte[2049];
            _r.nextBytes(_orig2049);
            
            byte[] _orig4097 = new byte[4097];
            _r.nextBytes(_orig4097);
            
            byte[] _orig8193 = new byte[8193];
            _r.nextBytes(_orig8193);
            
            byte[] _enc1025 = Hex.encode(_orig1025);
            byte[] _enc2049 = Hex.encode(_orig2049);
            byte[] _enc4097 = Hex.encode(_orig4097);
            byte[] _enc8193 = Hex.encode(_orig8193);
            
            byte[] _dec1025 = Hex.decode(_enc1025);
            byte[] _dec2049 = Hex.decode(_enc2049);
            byte[] _dec4097 = Hex.decode(_enc4097);
            byte[] _dec8193 = Hex.decode(_enc8193);
            
            if(!Arrays.equals(_orig1025, _dec1025)) {
                return new SimpleTestResult(false, "Failed Hex test");
            }
            
            if(!Arrays.equals(_orig2049, _dec2049)) {
                return new SimpleTestResult(false, "Failed Hex test");
            }
            
            if(!Arrays.equals(_orig4097, _dec4097)) {
                return new SimpleTestResult(false, "Failed Hex test");
            }
            
            if(!Arrays.equals(_orig8193, _dec8193)) {
                return new SimpleTestResult(false, "Failed Hex test");
            }
            
            return new SimpleTestResult(true, "Passed Hex test");
        }
        catch(Exception ex) {
            log(ex);
            return new SimpleTestResult(false, "Failed Hex test");
        }
    }
}
