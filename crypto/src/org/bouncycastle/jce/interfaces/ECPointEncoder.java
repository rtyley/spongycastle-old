package org.bouncycastle.jce.interfaces;

/**
 * All BC elliptic curve keys implement this interface. You need to
 * cast the key to get access to it.
 * <p>
 * By default BC keys produce encodings with point compression,
 * to turn this off call setPointFormat() with "UNCOMPRESSED".
 */
public interface ECPointEncoder
{
    /**
     * Set the formatting for encoding of points. If the String "UNCOMPRESSED" is passed
     * in point compression will not be used. The default is "COMPRESSED".
     * 
     * @param style the style to use.
     */
    public void setPointFormat(String style);
}
