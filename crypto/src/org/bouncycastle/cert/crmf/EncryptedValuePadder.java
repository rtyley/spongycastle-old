package org.bouncycastle.cert.crmf;

public interface EncryptedValuePadder
{
    byte[] getPaddedData(byte[] data);

    byte[] getUnpaddedData(byte[] paddedData);
}
